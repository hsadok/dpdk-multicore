#!/usr/bin/env python3

import os
import signal
import subprocess
import sys
import time

from pathlib import Path

import paramiko

EVAL_PATH = '/users/sadok/multicore_experiment'

# pktgen config
PKTGEN_EXEC = ('sudo /opt/pktgen-dpdk-mlx/app/' +
               'x86_64-native-linuxapp-gcc/pktgen')
PKTGEN_CORE_LIST = '1,2,3,4,5,6,7,8'
PKTGEN_PORT_ADDR = '41:00.0'
PKTGEN_CORE_MAP = '"[3:5-9].0"'
PKTGEN_SCRIPT = f'{EVAL_PATH}/set_pktgen.lua'
PKTGEN_RANGE_SCRIPT = f'{EVAL_PATH}/set_pktgen_range.lua'
PKTGEN_COMMAND = (f'source /users/sadok/AuditBox/set_machine.sh; ' +
                  f'{PKTGEN_EXEC} -l {PKTGEN_CORE_LIST} -n 4 -w ' +
                  f'{PKTGEN_PORT_ADDR} -- -P -m {PKTGEN_CORE_MAP} ' +
                  f'-f {PKTGEN_SCRIPT}')
PKTGEN_RANGE_COMMAND = (f'source /users/sadok/AuditBox/set_machine.sh; ' +
                        f'{PKTGEN_EXEC} -l {PKTGEN_CORE_LIST} -n 4 -w ' +
                        f'{PKTGEN_PORT_ADDR} -- -P -m {PKTGEN_CORE_MAP} ' +
                        f'-f {PKTGEN_RANGE_SCRIPT}')
PKTGEN_BPS_FILES = '/users/sadok/bps*.txt'
PKTGEN_PPS_FILES = '/users/sadok/pps*.txt'


# moongen config
EXPERIMENT_DURATION = 22 # seconds
PKT_SIZES = '64 128 256 512 1024'
RESULTS_PATH = '/mnt/storage/artifacts'
PKT_CORRECT_PCAP_PATH = '/mnt/storage/pcaps/gateway_pkt_level'
FLOW_CORRECT_PCAP_PATH = '/mnt/storage/pcaps/gateway_flow_level'
MOONGEN_FILES = f'{RESULTS_PATH}/mg*.csv'
FLOW = True   # turn this to True in order to run experiments with flow
              # (must also make sure to recompile AuditBox with flow enabled)


# common config

# auditbox config
AUDITBOX_DIR = '/users/sadok/AuditBox/AuditBox'
AUDITBOX_SGX_OPTIONS = (f'{AUDITBOX_DIR}/fwsgx/target/release/e2d2sgx.sgxs ' +
                        f'{AUDITBOX_DIR}/fwsgx/target/release/e2d2sgx.sig ' +
                        '/users/sadok/load_enclave/le.sgx ' +
                        '/users/sadok/load_enclave/le_prod_css.bin')

# safebricks config
PORTS = '-p 01:00.1'
PORTS_MULTICORE = '-p 01:00.1 -p 01:00.1'
MASTER_CORE = '1'
SLAVE_CORES = '-c 2'
SLAVE_CORES_MULTICORE = '-c 2 -c 3'
SAFEBRICKS_DIR = '/users/sadok/AuditBox/SafeBricks'
SAFEBRICKS_SGX_OPTIONS=(f'{SAFEBRICKS_DIR}/fwsgx/target/release/e2d2sgx.sgxs '+
                        f'{SAFEBRICKS_DIR}/fwsgx/target/release/e2d2sgx.sig ' +
                        '/users/sadok/load_enclave/le.sgx ' +
                        '/users/sadok/load_enclave/le_prod_css.bin')

NETBRICKS_COMMAND = ''


def get_auditbox_cmd(nf_name, config_path, other_options=None):    
    if other_options is None:
        other_options = ''

    cmd = ('source /users/sadok/AuditBox/set_machine.sh; ' +
           f'{AUDITBOX_DIR}/build.sh run {nf_name} {AUDITBOX_SGX_OPTIONS} ' + 
           f'-t 0 {other_options} -f {config_path}')
    return cmd


def get_safebricks_cmd(nf_name, multi_core, other_options=None):
    if multi_core:
        slave_cores = SLAVE_CORES_MULTICORE
        ports = PORTS_MULTICORE
    else:
        slave_cores = SLAVE_CORES
        ports = PORTS

    cmd = ('source /users/sadok/AuditBox/set_machine.sh; ' +
           f'{SAFEBRICKS_DIR}/build.sh run ' +
           f'{nf_name} {SAFEBRICKS_SGX_OPTIONS} ' +
           f'{ports} -m {MASTER_CORE} {slave_cores} -t 0 {other_options}')
    return cmd


def get_moongen_cmd(tx, rx, pkt_sizes, experiment_duration, replay):
    cmd = (
        f'{EVAL_PATH}/run_moongen.sh '
        f'--tx {tx} --rx {rx} '
        f'--duration {experiment_duration} {pkt_sizes}'
    )
    if replay:
        if FLOW:
            cmd += f' --replay {FLOW_CORRECT_PCAP_PATH}'
        else:
            cmd += f' --replay {PKT_CORRECT_PCAP_PATH}'

    return cmd


def get_ssh_client(host):
    # adapted from https://gist.github.com/acdha/6064215
    client = paramiko.SSHClient()
    client._policy = paramiko.WarningPolicy()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_config = paramiko.SSHConfig()
    user_config_file = os.path.expanduser("~/.ssh/config")
    if os.path.exists(user_config_file):
        with open(user_config_file) as f:
            ssh_config.parse(f)

    cfg = {'hostname': host}

    user_config = ssh_config.lookup(host)

    for k in ('hostname', 'username', 'port'):
        if k in user_config:
            cfg[k] = user_config[k]

    if 'user' in user_config:
        cfg['username'] = user_config['user']

    if 'proxycommand' in user_config:
        cfg['sock'] = paramiko.ProxyCommand(user_config['proxycommand'])

    if 'identityfile' in user_config:
        cfg['pkey'] = paramiko.RSAKey.from_private_key_file(
                        user_config['identityfile'][0])

    client.connect(**cfg)

    return client


def remote_command(client, command, pty=False):
    transport = client.get_transport()
    session = transport.open_session()

    if pty:
        session.setblocking(0)
        session.get_pty()
    
    session.exec_command(command)

    return session


def download_file(host, remote_path, local_path):
    subprocess.run(['scp', '-r', f'{host}:{remote_path}', local_path])


def run_experiment(middlebox_commands, middlebox_servers, pktgen_server,
                   pktgen_command):
    print('middlebox_commands: ', middlebox_commands)
    print('middlebox_servers: ', middlebox_servers)
    print('pktgen_server: ', pktgen_server)
    print('pktgen_command: ', pktgen_command)

    signal.signal(signal.SIGINT, signal.default_int_handler)

    pktgen_ssh_client = get_ssh_client(pktgen_server)
    middleboxes = []
    middlebox_ssh_clients = []

    for cmd, server in zip(middlebox_commands, middlebox_servers):
        ssh_client = get_ssh_client(server)
        middleboxes.append(remote_command(ssh_client, cmd, pty=True))
        middlebox_ssh_clients.append(ssh_client)
    
    time.sleep(5) # ensure that middleboxes have started

    pktgen = remote_command(pktgen_ssh_client, pktgen_command, pty=True)

    # output_process = pktgen
    output_process = middleboxes[-1]  # output last NF in the chain

    try:
        while not pktgen.exit_status_ready():
            time.sleep(0.01)

            if output_process.recv_ready():
                data = output_process.recv(512)

                sys.stdout.write(data.decode('utf-8'))
                sys.stdout.flush()
            
            if output_process.recv_stderr_ready():
                data = output_process.recv_stderr(512)

                sys.stderr.write(data.decode('utf-8'))
                sys.stderr.flush()
    except KeyboardInterrupt:
        pktgen.close()
        raise
    finally:
        for middlebox, ssh_client in zip(middleboxes, middlebox_ssh_clients):
            middlebox.send('\x03')  # Ctrl+C
            time.sleep(1)
            try:
                middlebox.close()
            except paramiko.ssh_exception.ProxyCommandFailure:  # paramiko bug
                pass

            ssh_client.close()

        pktgen_ssh_client.close()
    

# def run_experiment_with_dpdk_pktgen(middlebox_command, destination_dir):
#     run_experiment(middlebox_command, PKTGEN_COMMAND, destination_dir)
#     os.makedirs(destination_dir, exist_ok=True)
#     download_file('beluga3', PKTGEN_BPS_FILES, destination_dir)
#     download_file('beluga3', PKTGEN_PPS_FILES, destination_dir)


def run_experiment_with_moongen(middlebox_commands, middlebox_servers,
        pktgen_server, destination_dir, replay):
    if middlebox_servers[0] == 'beluga20':
        tx = 1
    elif middlebox_servers[0] == 'beluga22':
        tx = 0
    else:
        sys.stderr.write('Use either beluga20 or beluga22 as first NF')
        sys.exit(1)
    
    if middlebox_servers[-1] == 'beluga20':
        rx = 1
    elif middlebox_servers[-1] == 'beluga22':
        rx = 0
    else:
        sys.stderr.write('Use either beluga20 or beluga22 as last NF')
        sys.exit(1)
    
    moongen_cmd = get_moongen_cmd(tx, rx, PKT_SIZES, EXPERIMENT_DURATION, replay)

    run_experiment(middlebox_commands, middlebox_servers, pktgen_server,
                   moongen_cmd)
    os.makedirs(destination_dir, exist_ok=True)
    download_file(pktgen_server, MOONGEN_FILES, destination_dir)


def main():
    if (len(sys.argv) != 2):
        sys.stderr.write(f'usage: {sys.argv[0]} <destination dir>\n')
        sys.exit(1)
    
    destination_dir = Path(sys.argv[1])

    exp_func = run_experiment_with_moongen

    pktgen_server = 'beluga3'

    def run_auditbox_delay(server_chain, test_type, delay, nb_macs, dest_file):
        cmds = []
        for s in server_chain:
            config_path = f'{EVAL_PATH}/test_configs/{test_type}/{s}.toml'
            cmd = get_auditbox_cmd(
                'zcsi-delay',
                config_path,
                f'-d {delay} -n {nb_macs}'
            )
            cmds.append(cmd)

        dest_path = destination_dir / dest_file
        exp_func(cmds, server_chain, pktgen_server, dest_path, True)

    middlebox_servers = ['beluga20']

    for d in [1, 10, 100, 1000, 10000]:
        for nb_macs in [0, 1, 2]:
            run_auditbox_delay(
                middlebox_servers,
                'single_core/single_nf',
                d,
                nb_macs,
                f'auditbox_delay_{nb_macs}_{d}'
            )
            run_auditbox_delay(
                middlebox_servers,
                'multi_core/single_nf',
                d,
                nb_macs,
                f'auditbox_delay_{nb_macs}_{d}_m'
            )
        if not FLOW:  # make sure we only do experiments with SafeBricks once
            exp_func(
                [get_safebricks_cmd('zcsi-delay', False, f'-d {d}')],
                middlebox_servers,
                pktgen_server,
                destination_dir / f'safebricks_delay_{d}',
                False  # do not replay with SafeBricks
            )
            exp_func(
                [get_safebricks_cmd('zcsi-delay', True, f'-d {d}')],
                middlebox_servers,
                pktgen_server,
                destination_dir / f'safebricks_delay_{d}_m',
                False  # do not replay with SafeBricks
            )

    exp_func(
        [
            get_auditbox_cmd(
                'zcsi-nat',
                f'{EVAL_PATH}/test_configs/single_core/single_nf/{middlebox_servers[0]}.toml',
            ),
        ],
        middlebox_servers,
        pktgen_server,
        destination_dir / 'auditbox_nat',
        True
    )

    exp_func(
        [
            get_auditbox_cmd(
                'zcsi-fw',
                f'{EVAL_PATH}/test_configs/single_core/single_nf/{middlebox_servers[0]}.toml',
            ),
        ],
        middlebox_servers,
        pktgen_server,
        destination_dir / 'auditbox_fw',
        True
    )

    exp_func(
        [
            get_auditbox_cmd(
                'zcsi-dpi',
                f'{EVAL_PATH}/test_configs/single_core/single_nf/{middlebox_servers[0]}.toml',
            ),
        ],
        middlebox_servers,
        pktgen_server,
        destination_dir / 'auditbox_dpi',
        True
    )

    if not FLOW:  # make sure we only do experiments with SafeBricks once
        exp_func(
            [
                get_safebricks_cmd(
                    'zcsi-nat',
                    False
                ),
            ],
            middlebox_servers,
            pktgen_server,
            destination_dir / 'safebricks_nat',
            False  # do not replay with SafeBricks
        )
        exp_func(
            [
                get_safebricks_cmd(
                    'zcsi-fw',
                    False
                ),
            ],
            middlebox_servers,
            pktgen_server,
            destination_dir / 'safebricks_fw',
            False  # do not replay with SafeBricks
        )
        exp_func(
            [
                get_safebricks_cmd(
                    'zcsi-dpi',
                    False
                ),
            ],
            middlebox_servers,
            pktgen_server,
            destination_dir / 'safebricks_dpi',
            False  # do not replay with SafeBricks
        )


    ### experiments with chain ###

    middlebox_servers = ['beluga20', 'beluga21', 'beluga22']

    for d in [1, 10, 100, 1000, 10000]:
        for nb_macs in [0, 1, 2]:
            run_auditbox_delay(
                middlebox_servers,
                'single_core/chaining1',
                d,
                nb_macs,
                f'auditbox_chaining1_delay_{nb_macs}_{d}'
            )
            run_auditbox_delay(
                middlebox_servers,
                'multi_core/chaining1',
                d,
                nb_macs,
                f'auditbox_chaining1_delay_{nb_macs}_{d}_m'
            )

    exp_func(
        [
            get_auditbox_cmd(
                'zcsi-fw',
                f'{EVAL_PATH}/test_configs/single_core/chaining1/{middlebox_servers[0]}.toml',
            ),
            get_auditbox_cmd(
                'zcsi-dpi',
                f'{EVAL_PATH}/test_configs/single_core/chaining1/{middlebox_servers[1]}.toml',
            ),
            get_auditbox_cmd(
                'zcsi-nat',
                f'{EVAL_PATH}/test_configs/single_core/chaining1/{middlebox_servers[2]}.toml',
            ),
        ],
        middlebox_servers,
        pktgen_server,
        destination_dir / 'auditbox_chaining1_fw_dpi_nat',
        True
    )

    # exp_func(get_auditbox_cmd('zcsi-audit-gateway', False, '-d 2'),
    #     destination_dir / 'auditbox_gateway')
    # exp_func(get_auditbox_cmd('zcsi-audit-gateway', True, '-d 2'),
    #     destination_dir / 'auditbox_gateway_m')


if __name__ == "__main__":
    main()
