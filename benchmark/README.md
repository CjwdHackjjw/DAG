# Benchmark Guide for Aliyun ECS

This document explains how to run benchmarks in this repository on the Aliyun ECS platform.

The benchmark framework is driven by Fabric tasks defined in `benchmark/fabfile.py`, and the cloud platform settings are stored in `benchmark/settings.json`.

## 1. Overview

This benchmark directory supports two modes:

- local benchmarking on a single machine
- remote benchmarking on Aliyun ECS across multiple regions

For the current repository, the remote workflow is configured for **Aliyun**, not AWS.

Main files:

- `benchmark/fabfile.py`: benchmark tasks and experiment presets
- `benchmark/settings.json`: Aliyun account, SSH key, region, image, and network configuration
- `benchmark/results/`: generated benchmark summaries
- `benchmark/plots/`: generated figures

## 2. Prerequisites

Before running benchmarks, prepare the following on your local control machine:

- Python 3
- `pip`
- Fabric dependencies from `requirements.txt`
- a usable SSH private key
- a valid Aliyun account with ECS permissions
- properly configured VPC / VSwitch / security group resources in each target region

Install Python dependencies:

```bash
cd /home/DAG/Opencode/FREE/benchmark
pip3 install -r requirements.txt
```

You should also ensure the codebase itself can build correctly before launching remote experiments:

```bash
cd /home/DAG/Opencode/FREE
cargo build --release
```

## 3. Aliyun Configuration

Remote experiments are controlled by `benchmark/settings.json`.

The current file contains these important sections:

- `provider`: should be `aliyun`
- `ssh_user`: remote login user
- `key`: local SSH private key path and key-pair name
- `repo`: repository URL and branch to deploy remotely
- `instances`: ECS instance type and target regions
- `aliyun.region_config`: region-specific security group, VSwitch, bandwidth, and image settings

### 3.1 Key fields

#### SSH key

```json
"key": {
    "name": "xxx",
    "path": "/home/xxx/.ssh/aws"
}
```

You must make sure:

- the private key file exists locally
- the corresponding public key has been imported to Aliyun as an ECS key pair
- the key-pair name matches `key_pair_name`

#### Repository source

```json
"repo": {
    "name": "xxx",
    "url": "https://gitee.com/cjwdjjw/dag.git",
    "branch": "CJWD_ALI"
}
```

Remote machines will pull this repository and branch when you run `fab install` or remote benchmark tasks.

#### ECS instance configuration

```json
"instances": {
    "name": "dag-node",
    "type": "ecs.c6.xlarge",
    "regions": [
        "cn-hangzhou",
        "cn-beijing",
        "cn-qingdao",
        "cn-shanghai",
        "cn-shenzhen"
    ]
}
```

This means the benchmark platform will create ECS instances in the listed Aliyun regions.

#### Region-specific network configuration

Each region needs its own:

- `security_group_id`
- `vswitch_id`
- `image_id`
- public bandwidth configuration

For example:

```json
"cn-hangzhou": {
    "security_group_id": "...",
    "vswitch_id": "...",
    "internet_max_bandwidth_out": 5,
    "internet_charge_type": "PayByTraffic",
    "image_id": "ubuntu_22_04_x64_20G_alibase_20260316.vhd"
}
```

### 3.2 What you should verify before running

Before starting experiments, check:

- `access_key_id` and `access_key_secret` are valid
- every region in `instances.regions` has a matching entry in `aliyun.region_config`
- every `security_group_id` and `vswitch_id` exists and is usable
- the ECS image ID is valid in that region
- the SSH key can log in to created ECS instances
- the repository branch contains the code you want to benchmark

## 4. List Available Fabric Tasks

Run:

```bash
cd /home/DAG/Opencode/FREE/benchmark
fab --list
```

Common tasks include:

- `fab create`
- `fab start`
- `fab stop`
- `fab destroy`
- `fab info`
- `fab install`
- `fab remote`
- `fab remote_freeze`
- `fab remote_duration`
- `fab remote_imbalance`
- `fab logs`
- `fab plot`
- `fab kill`

## 5. Aliyun Remote Workflow

A typical Aliyun ECS benchmark workflow is:

```bash
cd /home/DAG/Opencode/FREE/benchmark
fab create
fab start
fab info
fab install
fab remote
```

After experiments:

```bash
fab stop
```

If you no longer need the machines:

```bash
fab destroy
```

## 6. Step-by-Step Usage

### Step 1: Create the ECS testbed

```bash
cd /home/DAG/Opencode/FREE/benchmark
fab create
```

By default, `fabfile.py` defines:

```python
@task
def create(ctx, nodes=2):
```

This means the system will try to create `nodes` machines per region, depending on the internal implementation of the instance manager and the configured Aliyun provider.

If you want to change the scale, edit the `nodes` argument in `fabfile.py` or pass a value explicitly if your Fabric setup supports it.

### Step 2: Start the machines

```bash
fab start
```

This is useful if the testbed already exists but is currently stopped.

### Step 3: Inspect machine information

```bash
fab info
```

Use this to verify:

- public IPs
- region placement
- machine availability
- SSH connectivity information

### Step 4: Install code on remote machines

```bash
fab install
```

This step typically:

- installs required dependencies on ECS instances
- clones or updates the configured repository
- prepares the benchmark environment

Run this again after changing the deployed branch or benchmark code.

### Step 5: Run the main remote benchmark

```bash
fab remote
```

Current preset in `benchmark/fabfile.py`:

```python
bench_params = {
    'faults': 0,
    'nodes': [50],
    'workers': 1,
    'collocate': True,
    'rate': [2250],
    'tx_size': 512,
    'duration': 150,
    'runs': 1,
}
```

Current node parameters:

```python
node_params = {
    'header_size': 50,
    'max_header_delay': 10_0000,
    'gc_depth': 50,
    'sync_retry_delay': 10_000,
    'sync_retry_nodes': 3,
    'batch_size': 500_000,
    'max_batch_delay': 200,
    'freeze_check_interval': 25,
}
```

Results are typically written into `benchmark/results/`.

## 7. Built-in Experiment Tasks

### 7.1 Freeze interval sweep

```bash
fab remote_freeze
```

This sweeps:

- `freeze_check_interval` in `[10, 15, 25, 35, 45, 55, 65]`

Preset:

- `faults = 3`
- `nodes = [10]`
- `rate = [1000]`
- `duration = 150`
- `runs = 1`

Output files are saved with suffixes like:

- `-fci-10.txt`
- `-fci-15.txt`
- `-fci-25.txt`

### 7.2 Duration sweep

```bash
fab remote_duration
```

This sweeps:

- `duration` in `[90, 150, 300, 450, 600]`

Preset:

- `faults = 1`
- `nodes = [10]`
- `rate = [1000]`
- `runs = 2`
- `freeze_check_interval = 25`

Output files are saved with suffixes like:

- `-dur-90.txt`
- `-dur-150.txt`
- `-dur-300.txt`

### 7.3 Load imbalance experiment

```bash
fab remote_imbalance
```

This compares:

- `balanced`
- `mild_imbalance`
- `heavy_imbalance`

Preset:

- `faults = 0`
- `nodes = [10]`
- `rate = [1000]`
- `duration = 150`
- `runs = 2`

## 8. Logs, Results, and Plotting

### Print parsed log summary

```bash
fab logs
```

### Kill still-running remote benchmark processes

```bash
fab kill
```

### Generate plots

```bash
fab plot
```

The current plotting preset is:

- `faults = [0]`
- `nodes = [10, 20, 50]`
- `workers = [1]`
- `collocate = True`
- `tx_size = 512`
- `max_latency = [3500, 4500]`

Plots are typically written to `benchmark/plots/`.

## 9. Local Benchmark

If you only want to validate functionality quickly on one machine:

```bash
cd /home/DAG/Opencode/FREE/benchmark
fab local
```

Current local preset:

- `faults = 0`
- `nodes = 5`
- `workers = 1`
- `rate = 50000`
- `tx_size = 512`
- `duration = 20`
- `freeze_check_interval = 15`

## 10. Recommended Reproducibility Checklist

For each experiment, record:

- git commit ID
- deployed branch from `settings.json`
- Aliyun regions used
- ECS instance type
- benchmark parameters from `fabfile.py`
- generated result files in `benchmark/results/`
- generated figures in `benchmark/plots/`

## 11. Notes

- Because this repository now targets Aliyun, old AWS-oriented instructions are not suitable here.
- If you change VSwitch, image, or security-group resources, update `benchmark/settings.json` first.
- If remote deployment fails, first verify region-specific network resources and SSH key setup.
