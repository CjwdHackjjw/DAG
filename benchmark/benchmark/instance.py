# Copyright(C) Facebook, Inc. and its affiliates.
import json
from collections import OrderedDict, defaultdict
from time import sleep

import boto3
from botocore.exceptions import ClientError

from benchmark.settings import Settings, SettingsError
from benchmark.utils import BenchError, Print, progress_bar

try:
    from aliyunsdkcore.client import AcsClient
    from aliyunsdkcore.acs_exception.exceptions import ClientException, ServerException
    from aliyunsdkecs.request.v20140526.CreateInstanceRequest import CreateInstanceRequest
    from aliyunsdkecs.request.v20140526.DeleteInstanceRequest import DeleteInstanceRequest
    from aliyunsdkecs.request.v20140526.DescribeInstancesRequest import DescribeInstancesRequest
    from aliyunsdkecs.request.v20140526.StartInstanceRequest import StartInstanceRequest
    from aliyunsdkecs.request.v20140526.StopInstanceRequest import StopInstanceRequest
except ImportError:
    AcsClient = None
    ClientException = Exception
    ServerException = Exception


class AWSError(Exception):
    def __init__(self, error):
        assert isinstance(error, ClientError)
        self.message = error.response['Error']['Message']
        self.code = error.response['Error']['Code']
        super().__init__(self.message)


class AliyunError(Exception):
    pass


class AWSInstanceManager:
    SECURITY_GROUP_NAME = 'dag'

    def __init__(self, settings):
        assert isinstance(settings, Settings)
        self.settings = settings
        self.clients = OrderedDict((r, boto3.client('ec2', region_name=r)) for r in settings.regions)

    def _get(self, states):
        ids, ips = defaultdict(list), defaultdict(list)
        for region, client in self.clients.items():
            res = client.describe_instances(Filters=[
                {'Name': 'tag:Name', 'Values': [self.settings.instance_name]},
                {'Name': 'instance-state-name', 'Values': states},
            ])
            instances = [y for x in res['Reservations'] for y in x['Instances']]
            for x in instances:
                ids[region].append(x['InstanceId'])
                if 'PublicIpAddress' in x:
                    ips[region].append(x['PublicIpAddress'])
        return ids, ips

    def _wait(self, states):
        while True:
            sleep(1)
            ids, _ = self._get(states)
            if sum(len(v) for v in ids.values()) == 0:
                break

    def _create_security_group(self, client):
        client.create_security_group(Description='HotStuff node', GroupName=self.SECURITY_GROUP_NAME)
        client.authorize_security_group_ingress(
            GroupName=self.SECURITY_GROUP_NAME,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Debug SSH access'}],
                    'Ipv6Ranges': [{'CidrIpv6': '::/0', 'Description': 'Debug SSH access'}],
                },
                {
                    'IpProtocol': 'tcp', 'FromPort': self.settings.base_port,
                    'ToPort': self.settings.base_port + 2000,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Dag port'}],
                    'Ipv6Ranges': [{'CidrIpv6': '::/0', 'Description': 'Dag port'}],
                },
            ],
        )

    def _get_ami(self, client):
        response = client.describe_images(
            Owners=['099720109477'],
            Filters=[
                {'Name': 'name', 'Values': ['ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*']},
                {'Name': 'state', 'Values': ['available']},
            ],
        )
        images = sorted(response.get('Images', []), key=lambda x: x['CreationDate'], reverse=True)
        if not images:
            raise RuntimeError('No Ubuntu 22.04 AMI found in this region')
        return images[0]['ImageId']

    def create_instances(self, instances):
        assert isinstance(instances, int) and instances > 0
        for client in self.clients.values():
            try:
                self._create_security_group(client)
            except ClientError as e:
                err = AWSError(e)
                if err.code != 'InvalidGroup.Duplicate':
                    raise BenchError('Failed to create security group', err)
        try:
            size = instances * len(self.clients)
            for client in progress_bar(self.clients.values(), prefix=f'Creating {size} instances'):
                client.run_instances(
                    ImageId=self._get_ami(client),
                    InstanceType=self.settings.instance_type,
                    KeyName=self.settings.key_name,
                    MaxCount=instances,
                    MinCount=instances,
                    SecurityGroups=[self.SECURITY_GROUP_NAME],
                    TagSpecifications=[{'ResourceType': 'instance', 'Tags': [{'Key': 'Name', 'Value': self.settings.instance_name}]}],
                    EbsOptimized=True,
                    BlockDeviceMappings=[{'DeviceName': '/dev/sda1', 'Ebs': {'VolumeType': 'gp2', 'VolumeSize': 200, 'DeleteOnTermination': True}}],
                )
            Print.info('Waiting for all instances to boot...')
            self._wait(['pending'])
            Print.heading(f'Successfully created {size} new instances')
        except ClientError as e:
            raise BenchError('Failed to create AWS instances', AWSError(e))

    def terminate_instances(self):
        try:
            ids, _ = self._get(['pending', 'running', 'stopping', 'stopped'])
            size = sum(len(v) for v in ids.values())
            if size == 0:
                Print.heading('All instances are shut down')
                return
            for region, client in self.clients.items():
                if ids[region]:
                    client.terminate_instances(InstanceIds=ids[region])
            Print.info('Waiting for all instances to shut down...')
            self._wait(['shutting-down'])
            for client in self.clients.values():
                client.delete_security_group(GroupName=self.SECURITY_GROUP_NAME)
            Print.heading(f'Testbed of {size} instances destroyed')
        except ClientError as e:
            raise BenchError('Failed to terminate instances', AWSError(e))

    def start_instances(self, max):
        size = 0
        try:
            ids, _ = self._get(['stopping', 'stopped'])
            for region, client in self.clients.items():
                target = ids[region] if len(ids[region]) < max else ids[region][:max]
                if target:
                    size += len(target)
                    client.start_instances(InstanceIds=target)
            Print.heading(f'Starting {size} instances')
        except ClientError as e:
            raise BenchError('Failed to start instances', AWSError(e))

    def stop_instances(self):
        try:
            ids, _ = self._get(['pending', 'running'])
            for region, client in self.clients.items():
                if ids[region]:
                    client.stop_instances(InstanceIds=ids[region])
            Print.heading(f'Stopping {sum(len(v) for v in ids.values())} instances')
        except ClientError as e:
            raise BenchError(AWSError(e))

    def hosts(self, flat=False):
        try:
            _, ips = self._get(['pending', 'running'])
            return [x for y in ips.values() for x in y] if flat else ips
        except ClientError as e:
            raise BenchError('Failed to gather instances IPs', AWSError(e))

    def print_info(self):
        hosts = self.hosts()
        text = ''
        for region, ips in hosts.items():
            text += f'\n Region: {region.upper()}\n'
            for i, ip in enumerate(ips):
                new_line = '\n' if (i + 1) % 6 == 0 else ''
                text += f'{new_line} {i}\tssh -i {self.settings.key_path} {self.settings.ssh_user}@{ip}\n'
        print('\n----------------------------------------------------------------\n INFO:\n----------------------------------------------------------------\n'
              f' Available machines: {sum(len(v) for v in hosts.values())}\n{text}'
              '----------------------------------------------------------------\n')


class AliyunInstanceManager:
    def __init__(self, settings):
        assert isinstance(settings, Settings)
        if AcsClient is None:
            raise BenchError('Aliyun SDK is not installed', ImportError('install aliyun-python-sdk-core and aliyun-python-sdk-ecs'))
        self.settings = settings
        self.clients = OrderedDict((r, AcsClient(settings.aliyun_access_key_id, settings.aliyun_access_key_secret, r)) for r in settings.regions)

    def _describe(self, region, statuses=None):
        req = DescribeInstancesRequest()
        req.set_accept_format('json')
        req.set_RegionId(region)
        req.set_InstanceName(self.settings.instance_name)
        if statuses:
            req.set_Statuses(statuses)
        return json.loads(self.clients[region].do_action_with_exception(req))

    def _get(self, statuses):
        ids, ips = defaultdict(list), defaultdict(list)
        for region in self.clients:
            try:
                instances = self._describe(region, statuses).get('Instances', {}).get('Instance', [])
                for inst in instances:
                    iid = inst.get('InstanceId')
                    if iid:
                        ids[region].append(iid)
                    pub = inst.get('PublicIpAddress', {}).get('IpAddress', [])
                    if pub:
                        ips[region].append(pub[0])
            except (ClientException, ServerException) as e:
                raise BenchError('Failed to describe aliyun instances', AliyunError(str(e)))
        return ids, ips

    def _wait(self, statuses):
        while True:
            sleep(2)
            ids, _ = self._get(statuses)
            if sum(len(v) for v in ids.values()) == 0:
                break

    def create_instances(self, instances):
        assert isinstance(instances, int) and instances > 0
        try:
            size = instances * len(self.clients)
            for region in progress_bar(list(self.clients.keys()), prefix=f'Creating {size} instances'):
                cfg = self.settings.aliyun_region_config[region]
                for _ in range(instances):
                    req = CreateInstanceRequest()
                    req.set_accept_format('json')
                    req.set_RegionId(region)
                    req.set_InstanceType(self.settings.instance_type)
                    req.set_SecurityGroupId(cfg['security_group_id'])
                    req.set_VSwitchId(cfg['vswitch_id'])
                    req.set_ImageId(cfg.get('image_id', 'ubuntu_22_04_x64_20G_alibase_20240218.vhd'))
                    req.set_InstanceName(self.settings.instance_name)
                    req.set_InternetMaxBandwidthOut(cfg.get('internet_max_bandwidth_out', 100))
                    req.set_InternetChargeType(cfg.get('internet_charge_type', 'PayByTraffic'))
                    req.set_SystemDiskCategory(cfg.get('system_disk_category', 'cloud_essd'))
                    req.set_SystemDiskSize(cfg.get('system_disk_size', 200))
                    req.set_InstanceChargeType(cfg.get('instance_charge_type', 'PostPaid'))
                    req.set_KeyPairName(self.settings.aliyun_key_pair_name)
                    iid = json.loads(self.clients[region].do_action_with_exception(req)).get('InstanceId')
                    if iid:
                        s = StartInstanceRequest(); s.set_accept_format('json'); s.set_InstanceId(iid)
                        self.clients[region].do_action_with_exception(s)
            Print.info('Waiting for all instances to boot...')
            self._wait(['Starting'])
            Print.heading(f'Successfully created {size} new instances')
        except (ClientException, ServerException) as e:
            raise BenchError('Failed to create Aliyun instances', AliyunError(str(e)))

    def terminate_instances(self):
        try:
            ids, _ = self._get(['Running', 'Stopped', 'Starting', 'Stopping'])
            size = sum(len(v) for v in ids.values())
            if size == 0:
                Print.heading('All instances are shut down')
                return
            for region in self.clients:
                for iid in ids[region]:
                    req = DeleteInstanceRequest(); req.set_accept_format('json'); req.set_InstanceId(iid); req.set_Force(True)
                    self.clients[region].do_action_with_exception(req)
            Print.heading(f'Testbed of {size} instances destroyed')
        except (ClientException, ServerException) as e:
            raise BenchError('Failed to terminate Aliyun instances', AliyunError(str(e)))

    def start_instances(self, max):
        size = 0
        try:
            ids, _ = self._get(['Stopped'])
            for region in self.clients:
                target = ids[region] if len(ids[region]) < max else ids[region][:max]
                for iid in target:
                    req = StartInstanceRequest(); req.set_accept_format('json'); req.set_InstanceId(iid)
                    self.clients[region].do_action_with_exception(req)
                size += len(target)
            Print.heading(f'Starting {size} instances')
        except (ClientException, ServerException) as e:
            raise BenchError('Failed to start Aliyun instances', AliyunError(str(e)))

    def stop_instances(self):
        try:
            ids, _ = self._get(['Running', 'Starting'])
            for region in self.clients:
                for iid in ids[region]:
                    req = StopInstanceRequest(); req.set_accept_format('json'); req.set_InstanceId(iid); req.set_ForceStop(True)
                    self.clients[region].do_action_with_exception(req)
            Print.heading(f'Stopping {sum(len(v) for v in ids.values())} instances')
        except (ClientException, ServerException) as e:
            raise BenchError('Failed to stop Aliyun instances', AliyunError(str(e)))

    def hosts(self, flat=False):
        _, ips = self._get(['Running', 'Starting'])
        return [x for y in ips.values() for x in y] if flat else ips

    def print_info(self):
        hosts = self.hosts()
        text = ''
        for region, ips in hosts.items():
            text += f'\n Region: {region.upper()}\n'
            for i, ip in enumerate(ips):
                new_line = '\n' if (i + 1) % 6 == 0 else ''
                text += f'{new_line} {i}\tssh -i {self.settings.key_path} {self.settings.ssh_user}@{ip}\n'
        print('\n----------------------------------------------------------------\n INFO:\n----------------------------------------------------------------\n'
              f' Available machines: {sum(len(v) for v in hosts.values())}\n{text}'
              '----------------------------------------------------------------\n')


class InstanceManager:
    @classmethod
    def make(cls, settings_file='settings.json'):
        try:
            settings = Settings.load(settings_file)
            return AliyunInstanceManager(settings) if settings.provider == 'aliyun' else AWSInstanceManager(settings)
        except SettingsError as e:
            raise BenchError('Failed to load settings', e)
