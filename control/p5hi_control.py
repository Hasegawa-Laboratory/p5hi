import os
import sys
import ipaddress
import hashlib
from scapy.all import *

import phiutils
import controlutils

sys.path.append(os.path.expandvars('/root/bf-sde-9.13.0/install/lib/python3.7/site-packages/tofino/bfrt_grpc'))
sys.path.append(os.path.expandvars('/root/bf-sde-9.13.0/install/lib/python3.7/site-packages/tofino/'))
sys.path.append(os.path.expandvars('/root/bf-sde-9.13.0/install/lib/python3.7/site-packages/'))

import bfrt_grpc.client as gc

FIB_AP_SIZE = 10320
SPLIT_FIB = True

SWITCH_ADDR = '45.115.57.0'
ENC_KEYS = [0x0123456789abcdef, 0x123456789abcdef0]
AUTH_KEYS = [0x23456789abcdef01, 0x3456789abcdef012]


SIP_CONST = [0x736f6d6570736575, 0x646f72616e646f6d, 0x6c7967656e657261, 0x7465646279746573]


# =======================


ns = 22
flow_size = 80
setup_paysize = 100
data_fw_paysize = 870
data_bw_paysize = 870


# packet types
[enb_3_0, enb_3_1, enb_0_0, enb_1_0] = [True, True, True, True]

# =======================


skip_fib = len(sys.argv) > 1 and sys.argv[1] == 'skipfib'
n_pipes = 4 if SPLIT_FIB else 1

out_ports = [8, 16, 136, 144, 312, 320, 440, 448]
next_addr = ['42.115.43.219', '212.92.125.45', '169.216.80.170', '2.16.6.0', \
    '172.106.136.182', '8.27.24.0', '45.115.42.0', '1.0.136.0']


if not skip_fib:
    print('Creating FIB...')
    fib = {}
    addr = {}
    with open('./bgp_fib/rib_wain.txt') as f:
        for line in f:
            line = line.rstrip()
            
            prefix = ipaddress.ip_network(line.split(' ')[0], strict=False)
            netaddr = prefix.network_address
            netmask = prefix.netmask
            fib[(netaddr, netmask)] = 0
            # nextaddr = ipaddress.ip_address(unicode(line.split(' ')[1]))
            # addr[(netaddr, netmask)] = int(nextaddr)
            addr[(netaddr, netmask)] = 0  
    

    for i, key in enumerate(fib):
        h = hashlib.md5((str(key[0]) + str(key[1])).encode('utf-8')).hexdigest()
        fib[key] = out_ports[int(h, 16) % len(out_ports)]
        addr[key] = int(ipaddress.ip_address(next_addr[int(h, 16) % len(out_ports)]))


    fibs = [{}, {}, {}, {}]
    addrs = [{}, {}, {}, {}]
    pipe_map = {0x00000000: 0, 0x01000000: 1, 0x10000000: 2, 0x11000000: 3}

    for key in fib:
        int_addr = int(key[0])
        pipe = pipe_map[int_addr & 0x11000000] if SPLIT_FIB else 0
        fibs[pipe][key] = fib[key]
        addrs[pipe][key] = addr[key]
        
    #forwarding_ap
    fib_ap = {}
    addr_ap = {}

    with open('./igp_fib/fib.txt') as f:
        for i in range(FIB_AP_SIZE):
            line = f.readline()
            line = line.rstrip()
            
            prefix = ipaddress.ip_network(line.split(' ')[0], strict=False)
            netaddr = prefix.network_address
            netmask = prefix.netmask
            fib_ap[(netaddr, netmask)] = 0
            addr_ap[(netaddr, netmask)] = 0


    for i, key in enumerate(fib_ap):
        h = hashlib.md5((str(key[0]) + str(key[1])).encode('utf-8')).hexdigest()
        fib_ap[key] = out_ports[int(h, 16) % len(out_ports)]
        addr_ap[key] = int(ipaddress.ip_address(next_addr[int(h, 16) % len(out_ports)]))


print('Connecting to Tofino...')
grpc_addr = 'localhost:50052'
client_id = 0
device_id = 0
is_master = False
notifications = None
perform_bind = True

interface = gc.ClientInterface(grpc_addr, client_id=1, device_id=0)
# interface = gc.ClientInterface(grpc_addr, client_id=client_id, device_id=device_id, is_master=is_master, notifications=notifications)
bfrt_info = interface.bfrt_info_get()
p4_name = bfrt_info.p4_name_get()
if perform_bind:
    interface.bind_pipeline_config(p4_name)
target = gc.Target(device_id=0, pipe_id=0xFFFF)


for stored_pipe in range(n_pipes):
    print('Setting keys #%d...' % stored_pipe)

    key_list = []
    data_list = []
    init_table = bfrt_info.table_get('MyIngressControl%d.tb_initialize' % stored_pipe)
    init_table.entry_del(target)

    for i in range(4):
        key_list.append(init_table.make_key([gc.KeyTuple('hdr.phi.mode', i)]))
        data_list.append(init_table.make_data([
            gc.DataTuple('init_0_0', SIP_CONST[0] ^ ENC_KEYS[0]), 
            gc.DataTuple('init_0_1', SIP_CONST[1] ^ ENC_KEYS[1]), 
            gc.DataTuple('init_0_2', SIP_CONST[2] ^ ENC_KEYS[0]), 
            gc.DataTuple('init_0_3', SIP_CONST[3] ^ ENC_KEYS[1]), 
            gc.DataTuple('init_1_0', SIP_CONST[0] ^ AUTH_KEYS[0]), 
            gc.DataTuple('init_1_1', SIP_CONST[1] ^ AUTH_KEYS[1]), 
            gc.DataTuple('init_1_2', SIP_CONST[2] ^ AUTH_KEYS[0]), 
            gc.DataTuple('init_1_3', SIP_CONST[3] ^ AUTH_KEYS[1])
        ], 'MyIngressControl%d.initialize_v' % stored_pipe))

    init_table.entry_add(target, key_list, data_list)


    key_list = []
    data_list = []
    init_table = bfrt_info.table_get('MyIngressControl%d.tb_reinitialize' % stored_pipe)
    init_table.entry_del(target)

    for i in range(4):
        key_list.append(init_table.make_key([gc.KeyTuple('hdr.phi.mode', i)]))
        data_list.append(init_table.make_data([
            gc.DataTuple('init_1_0', SIP_CONST[0] ^ AUTH_KEYS[0]), 
            gc.DataTuple('init_1_1', SIP_CONST[1] ^ AUTH_KEYS[1]), 
            gc.DataTuple('init_1_2', SIP_CONST[2] ^ AUTH_KEYS[0]), 
            gc.DataTuple('init_1_3', SIP_CONST[3] ^ AUTH_KEYS[1])
        ], 'MyIngressControl%d.initialize_v1' % stored_pipe))

    init_table.entry_add(target, key_list, data_list)



for stored_pipe in range(n_pipes):
    print('Setting the switch\'s address #%d...' % stored_pipe)

    key_list = []
    data_list = []
    myaddr_table = bfrt_info.table_get('MyIngressControl%d.tb_myaddr' % stored_pipe)
    myaddr_table.entry_del(target)

    for i in range(4):
        key_list.append(myaddr_table.make_key([gc.KeyTuple('hdr.phi.mode', i)]))
        data_list.append(myaddr_table.make_data([
            gc.DataTuple('myaddr', int(ipaddress.ip_address(SWITCH_ADDR)))
        ], 'MyIngressControl%d.set_myaddr' % stored_pipe))

    myaddr_table.entry_add(target, key_list, data_list)



recir_ports = [
    [24, 32, 40, 48] * 2,
    [152, 160, 168, 176] * 2,
    [24, 32, 40, 48] * 2,
    [152, 160, 168, 176] * 2,
]

for stored_pipe in range(n_pipes):
    print('Adding recirculation rules #%d...' % stored_pipe)

    key_list = []
    data_list = []
    recir_table = bfrt_info.table_get('MyIngressControl%d.tb_set_recirculation_port' % stored_pipe)
    recir_table.entry_del(target)

    ip_proto = gc.KeyTuple('hdr.ipv4.protocol', 200, (1 << 8) - 1)
    ip_proto_X = gc.KeyTuple('hdr.ipv4.protocol', 0, 0)

    mode = gc.KeyTuple('hdr.phi.mode', 3, (1 << 2) - 1)
    mode_X = gc.KeyTuple('hdr.phi.mode', 0, 0)

    phase = gc.KeyTuple('hdr.phi.handshake_phase', 3, (1 << 2) - 1)
    phase_X = gc.KeyTuple('hdr.phi.handshake_phase', 0, 0)
    
    # PHI, P3, pass -> decide recirc. port randomly
    for remote_pipe in range(4):
        for i, recir_port in enumerate(recir_ports[remote_pipe]):
            rand_2 = gc.KeyTuple('hdr.meta.recirculation_random', i | remote_pipe << 3, (1 << 5) - 1)
            dst_X = gc.KeyTuple('hdr.phi.plain_dst', 0, 0)

            key_list.append(recir_table.make_key([ip_proto, mode, phase, rand_2, dst_X]))
            data_list.append(recir_table.make_data([gc.DataTuple('port', recir_port)], 'MyIngressControl%d.set_recirculation_port' % stored_pipe))

    # PHI, P0 or P1 or P2 -> decide recirc. port based on IP address
    for remote_pipe in range(4):
        for i, recir_port in enumerate(recir_ports[remote_pipe]):
            rand_1 = gc.KeyTuple('hdr.meta.recirculation_random', i, (1 << 3) - 1)
            dst = gc.KeyTuple('hdr.phi.plain_dst', [0x00000000, 0x01000000, 0x10000000, 0x11000000][remote_pipe], 0x11000000)

            key_list.append(recir_table.make_key([ip_proto, mode, phase_X, rand_1, dst]))
            data_list.append(recir_table.make_data([gc.DataTuple('port', recir_port)], 'MyIngressControl%d.set_recirculation_port' % stored_pipe))

    # PHI, D0 or D1 -> decide recirc. port randomly
    for remote_pipe in range(4):
        for i, recir_port in enumerate(recir_ports[remote_pipe]):
            rand_2 = gc.KeyTuple('hdr.meta.recirculation_random', i | remote_pipe << 3, (1 << 5) - 1)
            dst_X = gc.KeyTuple('hdr.phi.plain_dst', 0, 0)

            key_list.append(recir_table.make_key([ip_proto, mode_X, phase_X, rand_2, dst_X]))
            data_list.append(recir_table.make_data([gc.DataTuple('port', recir_port)], 'MyIngressControl%d.set_recirculation_port' % stored_pipe))

    # IP packet -> decide recirc. port based on IP address
    for remote_pipe in range(4):
        for i, recir_port in enumerate(recir_ports[remote_pipe]):
            rand_1 = gc.KeyTuple('hdr.meta.recirculation_random', i, (1 << 3) - 1)
            dst = gc.KeyTuple('hdr.phi.plain_dst', [0x00000000, 0x01000000, 0x10000000, 0x11000000][remote_pipe], 0x11000000)

            key_list.append(recir_table.make_key([ip_proto_X, mode_X, phase_X, rand_1, dst]))
            data_list.append(recir_table.make_data([gc.DataTuple('port', recir_port)], 'MyIngressControl%d.set_recirculation_port' % stored_pipe))

    recir_table.entry_add(target, key_list, data_list)
    



if not skip_fib:
    for pipe in range(n_pipes):
        print('Adding forwarding rules #%d...' % pipe)

        forwarding_table = bfrt_info.table_get('MyIngressControl%d.tb_forwarding' % pipe)
        forwarding_table.info.key_field_annotation_add("hdr.phi.plain_dst", "ipv4")
        forwarding_table.entry_del(target)
        
        key_list = []
        data_list = []
        for key in fibs[pipe]:
            key_list.append(
                forwarding_table.make_key([gc.KeyTuple('hdr.phi.plain_dst', str(key[0]), prefix_len=bin(int(key[1])).count('1'))]) 
            )
            data_list.append(
                forwarding_table.make_data([gc.DataTuple('egress_port', fibs[pipe][key]), gc.DataTuple('next_addr', addrs[pipe][key])], 'MyIngressControl%d.set_forwarding_port' % pipe) 
            )
        forwarding_table.entry_add(target, key_list, data_list)


    for pipe in range(n_pipes):
        print('Adding forwarding rules ap #%d...' % pipe)

        forwarding_table = bfrt_info.table_get('MyIngressControl%d.tb_forwarding_ap' % pipe)
        forwarding_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
        forwarding_table.entry_del(target)
        
        key_list = []
        data_list = []
        for key in fib_ap:
            key_list.append(
                forwarding_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr', str(key[0]), prefix_len=bin(int(key[1])).count('1'))]) 
            )
            data_list.append(
                forwarding_table.make_data([gc.DataTuple('egress_port', fib_ap[key])], 'MyIngressControl%d.forward' % pipe) 
            )
        forwarding_table.entry_add(target, key_list, data_list)




for stored_pipe in range(n_pipes):
    print('Adding port distribution rules #%d...' % stored_pipe)

    key_list = []
    data_list = []
    port_distribute_table = bfrt_info.table_get('MyIngressControl%d.tb_distribute_out' % stored_pipe)
    port_distribute_table.entry_del(target)

    for p in out_ports:
        for i in range(4):
            key_list.append(port_distribute_table.make_key([gc.KeyTuple('ig_tm_md.ucast_egress_port', p), gc.KeyTuple('hdr.meta.recirculation_random[6:5]', i)]))
            data_list.append(
                port_distribute_table.make_data([gc.DataTuple('egress_port', p + i * 2)], 'MyIngressControl%d.forward' % stored_pipe) 
            )

    port_distribute_table.entry_add(target, key_list, data_list)

