# FREE

FREE is a Rust implementation of a DAG-based protocol with Fabric-based benchmarking scripts.

## Quick Start

### Requirements

Install:

- Rust toolchain
- Python 3 + `pip`
- `tmux`
- `clang`
- build tools

Example on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y build-essential clang cmake pkg-config libssl-dev tmux python3 python3-pip
```

Install Python benchmark dependencies:

```bash
cd /home/DAG/Opencode/FREE/benchmark
pip3 install -r requirements.txt
```

Build the project:

```bash
cd /home/DAG/Opencode/FREE
cargo build --release
```

## Reproduce Experiments

### 1. Local experiment

```bash
cd /home/DAG/Opencode/FREE/benchmark
fab local
```

Current local preset in `benchmark/fabfile.py`:

- `faults = 0`
- `nodes = 5`
- `workers = 1`
- `rate = 50000`
- `tx_size = 512`
- `duration = 20`
- `freeze_check_interval = 15`

### 2. Default remote experiment

Remote settings are read from `benchmark/settings.json`.
Make sure the SSH key, cloud credentials, image IDs, and repo branch are correct before running.

Typical workflow:

```bash
cd /home/DAG/Opencode/FREE/benchmark
fab create
fab start
fab info
fab install
fab remote
```

Clean up:

```bash
fab stop
fab destroy
```

### 3. Other experiment tasks

All of the following are defined in `benchmark/fabfile.py`:

```bash
fab remote_freeze
fab remote_duration
fab remote_imbalance
fab plot
fab logs
fab kill
```

What they do:

- `fab remote_freeze`: sweep `freeze_check_interval`
- `fab remote_duration`: sweep experiment duration
- `fab remote_imbalance`: compare balanced vs imbalanced client load
- `fab plot`: generate plots from result files
- `fab logs`: print parsed log summary
- `fab kill`: stop remote benchmark processes

## Where to change parameters

Edit `benchmark/fabfile.py` if you want to change:

- `faults`
- `nodes`
- `workers`
- `rate`
- `duration`
- `runs`
- `header_size`
- `max_header_delay`
- `batch_size`
- `freeze_check_interval`
- `node_rate_weights`

## Results

Benchmark outputs are typically written under:

- `benchmark/results/`


## License

Licensed under [Apache 2.0](LICENSE).
