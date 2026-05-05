# Copyright(C) Facebook, Inc. and its affiliates.
from fabric import task

from benchmark.local import LocalBench
from benchmark.logs import ParseError, LogParser
from benchmark.utils import Print
from benchmark.plot import Ploter, PlotError
from benchmark.instance import InstanceManager
from benchmark.remote import Bench, BenchError
import os


@task
def local(ctx, debug=True):
    ''' Run benchmarks on localhost '''
    bench_params = {
        'faults': 0,
        'nodes': 5,
        'workers': 1,
        'rate': 50_000,
        'tx_size': 512,
        'duration': 20,
    }
    node_params = {
        'header_size': 1_000,  # bytes
        'max_header_delay': 200,  # ms
        'gc_depth': 50,  # rounds
        'sync_retry_delay': 10_000,  # ms
        'sync_retry_nodes': 3,  # number of nodes
        'batch_size': 500_000,  # bytes
        'max_batch_delay': 200,  # ms
        'freeze_check_interval': 15,
    }
    try:
        ret = LocalBench(bench_params, node_params).run(debug)
        print(ret.result())
    except BenchError as e:
        Print.error(e)


@task
def create(ctx, nodes=2):
    ''' Create a testbed'''
    try:
        InstanceManager.make().create_instances(nodes)
    except BenchError as e:
        Print.error(e)


@task
def destroy(ctx):
    ''' Destroy the testbed '''
    try:
        InstanceManager.make().terminate_instances()
    except BenchError as e:
        Print.error(e)


@task
def start(ctx, max=2):
    ''' Start at most `max` machines per data center '''
    try:
        InstanceManager.make().start_instances(max)
    except BenchError as e:
        Print.error(e)


@task
def stop(ctx):
    ''' Stop all machines '''
    try:
        InstanceManager.make().stop_instances()
    except BenchError as e:
        Print.error(e)


@task
def info(ctx):
    ''' Display connect information about all the available machines '''
    try:
        InstanceManager.make().print_info()
    except BenchError as e:
        Print.error(e)


@task
def install(ctx):
    ''' Install the codebase on all machines '''
    try:
        Bench(ctx).install()
    except BenchError as e:
        Print.error(e)


@task
def remote(ctx, debug=False):
    ''' Run benchmarks on AWS '''
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
    node_params = {
        'header_size': 50,  # bytes
        'max_header_delay': 10_0000,  # ms
        'gc_depth': 50,  # rounds
        'sync_retry_delay': 10_000,  # ms
        'sync_retry_nodes': 3,  # number of nodes
        'batch_size': 500_000,  # bytes
        'max_batch_delay': 200,  # ms
        'freeze_check_interval': 25,
    }
    try:
        Bench(ctx).run(bench_params, node_params, debug)
    except BenchError as e:
        Print.error(e)


@task
def remote_freeze(ctx, debug=False):
    ''' Sweep different freeze_check_interval values '''
    bench_params = {
        'faults': 3,
        'nodes': [10],
        'workers': 1,
        'collocate': True,
        'rate': [1000],
        'tx_size': 512,
        'duration': 150,
        'runs': 1,
    }
    base_node_params = {
        'header_size': 50,
        'max_header_delay': 15_000,
        'gc_depth': 50,
        'sync_retry_delay': 10_000,
        'sync_retry_nodes': 3,
        'batch_size': 500_000,
        'max_batch_delay': 200,
        'freeze_check_interval': 25,
    }
    freeze_list = [10, 15, 25, 35, 45, 55, 65]

    src = (
        f"results/bench-{bench_params['faults']}-"
        f"{bench_params['nodes'][0]}-{bench_params['workers']}-"
        f"{bench_params['collocate']}-{bench_params['rate'][0]}-"
        f"{bench_params['tx_size']}.txt"
    )

    for fci in freeze_list:
        Print.heading(f'\n=== freeze_check_interval = {fci} ===')
        node_params = dict(base_node_params)
        node_params['freeze_check_interval'] = fci

        # Clear src before each run to avoid mixing results from different FCI values.
        if os.path.exists(src):
            os.remove(src)

        try:
            Bench(ctx).run(bench_params, node_params, debug)
            if os.path.exists(src):
                dst = src.replace('.txt', f'-fci-{fci}.txt')
                with open(src, 'r') as sfile, open(dst, 'a') as dfile:
                    dfile.write(sfile.read())
                Print.info(f'Appended: {dst}')
        except BenchError as e:
            Print.error(e)

@task
def remote_duration(ctx, debug=False):
    ''' Sweep different duration values (fixed faults + fixed fci) '''
    bench_params = {
        'faults': 1,          
        'nodes': [10],
        'workers': 1,
        'collocate': True,
        'rate': [1000],
        'tx_size': 512,
        'duration': 150,      
        'runs': 2,
    }
    node_params = {
        'header_size': 50,
        'max_header_delay': 15_000,
        'gc_depth': 50,
        'sync_retry_delay': 10_000,
        'sync_retry_nodes': 3,
        'batch_size': 500_000,
        'max_batch_delay': 200,
        'freeze_check_interval': 25,   # fixed FCI
    }

    duration_list = [90, 150, 300, 450,600]

    src = (
        f"results/bench-{bench_params['faults']}-"
        f"{bench_params['nodes'][0]}-{bench_params['workers']}-"
        f"{bench_params['collocate']}-{bench_params['rate'][0]}-"
        f"{bench_params['tx_size']}.txt"
    )

    for dur in duration_list:
        Print.heading(f'\n=== duration = {dur}s ===')
        bench_params['duration'] = dur


        if os.path.exists(src):
            os.remove(src)

        try:
            Bench(ctx).run(bench_params, node_params, debug)
            if os.path.exists(src):
                dst = src.replace('.txt', f'-dur-{dur}.txt')
                with open(src, 'r') as sfile, open(dst, 'a') as dfile:
                    dfile.write(sfile.read())
                Print.info(f'Appended: {dst}')
        except BenchError as e:
            Print.error(e)

@task
def remote_imbalance(ctx, debug=False):
    """ Run 10-node 1000 tx/s benchmarks with balanced and imbalanced client rates """
    base_bench_params = {
        'faults': 0,
        'nodes': [10],
        'workers': 1,
        'collocate': True,
        'rate': [1000],
        'tx_size': 512,
        'duration': 150,
        'runs': 2,
    }
    node_params = {
        'header_size': 50,
        'max_header_delay': 15_000,
        'gc_depth': 50,
        'sync_retry_delay': 10_000,
        'sync_retry_nodes': 3,
        'batch_size': 500_000,
        'max_batch_delay': 200,
        'freeze_check_interval': 25,
    }
    load_patterns = {
        'balanced': [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        'mild_imbalance': [1, 1, 1, 1, 1, 2, 2, 2, 2, 2],
        'heavy_imbalance': [1, 1, 1, 1, 1, 1, 2, 4, 8, 16],
    }
    src = (
        f"results/bench-{base_bench_params['faults']}-"
        f"{base_bench_params['nodes'][0]}-{base_bench_params['workers']}-"
        f"{base_bench_params['collocate']}-{base_bench_params['rate'][0]}-"
        f"{base_bench_params['tx_size']}.txt"
    )

    for label, weights in load_patterns.items():
        Print.heading(f'\n=== {label} node_rate_weights = {weights} ===')
        bench_params = dict(base_bench_params)
        bench_params['node_rate_weights'] = weights

        if os.path.exists(src):
            os.remove(src)

        try:
            Bench(ctx).run(bench_params, node_params, debug)
            if os.path.exists(src):
                dst = src.replace('.txt', f'-{label}.txt')
                with open(src, 'r') as sfile, open(dst, 'a') as dfile:
                    dfile.write(sfile.read())
                Print.info(f'Appended: {dst}')
        except BenchError as e:
            Print.error(e)


@task
def plot(ctx):
    ''' Plot performance using the logs generated by "fab remote" '''
    plot_params = {
        'faults': [0],
        'nodes': [10, 20, 50],
        'workers': [1],
        'collocate': True,
        'tx_size': 512,
        'max_latency': [3_500, 4_500]
    }
    try:
        Ploter.plot(plot_params)
    except PlotError as e:
        Print.error(BenchError('Failed to plot performance', e))


@task
def kill(ctx):
    ''' Stop execution on all machines '''
    try:
        Bench(ctx).kill()
    except BenchError as e:
        Print.error(e)


@task
def logs(ctx):
    ''' Print a summary of the logs '''
    try:
        print(LogParser.process('./logs', faults='?').result())
    except ParseError as e:
        Print.error(BenchError('Failed to parse logs', e))
