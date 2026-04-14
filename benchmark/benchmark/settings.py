# Copyright(C) Facebook, Inc. and its affiliates.
from json import load, JSONDecodeError


class SettingsError(Exception):
    pass


class Settings:
    def __init__(
        self,
        key_name,
        key_path,
        base_port,
        repo_name,
        repo_url,
        branch,
        instance_type,
        regions,
        provider='aws',
        ssh_user='ubuntu',
        instance_name='dag-node',
        aliyun_access_key_id='',
        aliyun_access_key_secret='',
        aliyun_key_pair_name='',
        aliyun_region_config=None,
    ):
        aliyun_region_config = aliyun_region_config or {}
        regions = regions if isinstance(regions, list) else [regions]

        strings = [
            key_name,
            key_path,
            repo_name,
            repo_url,
            branch,
            instance_type,
            provider,
            ssh_user,
            instance_name,
            *regions,
        ]
        ok = all(isinstance(x, str) and len(x) > 0 for x in strings)
        ok &= isinstance(base_port, int)
        ok &= len(regions) > 0
        ok &= provider in ['aws', 'aliyun']
        ok &= isinstance(aliyun_region_config, dict)
        if not ok:
            raise SettingsError('Invalid settings types')

        if provider == 'aliyun':
            if not aliyun_access_key_id or not aliyun_access_key_secret:
                raise SettingsError('Missing aliyun access key id/secret')
            for region in regions:
                cfg = aliyun_region_config.get(region)
                if not isinstance(cfg, dict):
                    raise SettingsError(f'Missing aliyun region_config for {region}')
                if not cfg.get('security_group_id') or not cfg.get('vswitch_id'):
                    raise SettingsError(
                        f'Missing security_group_id/vswitch_id for aliyun region {region}'
                    )

        self.provider = provider
        self.ssh_user = ssh_user

        self.key_name = key_name
        self.key_path = key_path
        self.base_port = base_port

        self.repo_name = repo_name
        self.repo_url = repo_url
        self.branch = branch

        self.instance_type = instance_type
        self.regions = regions
        self.aws_regions = regions
        self.instance_name = instance_name

        self.aliyun_access_key_id = aliyun_access_key_id
        self.aliyun_access_key_secret = aliyun_access_key_secret
        self.aliyun_key_pair_name = aliyun_key_pair_name or key_name
        self.aliyun_region_config = aliyun_region_config

    @classmethod
    def load(cls, filename):
        try:
            with open(filename, 'r') as f:
                data = load(f)

            provider = data.get('provider', 'aws')
            instances = data['instances']
            aliyun = data.get('aliyun', {})

            return cls(
                data['key']['name'],
                data['key']['path'],
                data['port'],
                data['repo']['name'],
                data['repo']['url'],
                data['repo']['branch'],
                instances['type'],
                instances['regions'],
                provider=provider,
                ssh_user=data.get('ssh_user', 'ubuntu'),
                instance_name=instances.get('name', 'dag-node'),
                aliyun_access_key_id=aliyun.get('access_key_id', ''),
                aliyun_access_key_secret=aliyun.get('access_key_secret', ''),
                aliyun_key_pair_name=aliyun.get('key_pair_name', data['key']['name']),
                aliyun_region_config=aliyun.get('region_config', {}),
            )
        except (OSError, JSONDecodeError) as e:
            raise SettingsError(str(e))
        except KeyError as e:
            raise SettingsError(f'Malformed settings: missing key {e}')
