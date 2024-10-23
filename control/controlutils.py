import sys
import os

sys.path.append(os.path.expandvars('/root/bf-sde-9.13.0/install/lib/python3.7/site-packages/tofino/bfrt_grpc'))
sys.path.append(os.path.expandvars('/root/bf-sde-9.13.0/install/lib/python3.7/site-packages/tofino/'))
sys.path.append(os.path.expandvars('/root/bf-sde-9.13.0/install/lib/python3.7/site-packages/'))

import bfrt_grpc.client as gc


def try_entry_add(table, target, key_list, data_list):
    try:
        table.entry_add(target, key_list, data_list)
    except gc.BfruntimeReadWriteRpcException as ex:
        if 'Already exists' in str(ex):
            table.entry_mod(target, key_list, data_list)
        else:
            raise ex

def configure_multicast(target, bfrt_info, 
                        mgrp_id, rids, port_lists):
    
    assert len(rids) == len(port_lists)    

    mgid_table = bfrt_info.table_get("$pre.mgid")
    node_table = bfrt_info.table_get("$pre.node")
    
    mgid_key = mgid_table.make_key([gc.KeyTuple('$MGID', mgrp_id)])
    try_entry_add(mgid_table, target, [mgid_key], None)

    for rid, ports in zip(rids, port_lists):
        rid_key = node_table.make_key([gc.KeyTuple('$MULTICAST_NODE_ID', rid)])
        rid_data = node_table.make_data([gc.DataTuple('$MULTICAST_RID', rid), gc.DataTuple('$DEV_PORT', int_arr_val=ports)])
        try_entry_add(node_table, target, [rid_key], [rid_data])

    mgid_key = mgid_table.make_key([gc.KeyTuple('$MGID', mgrp_id)])
    mgid_data = mgid_table.make_data([
        gc.DataTuple('$MULTICAST_NODE_ID', int_arr_val=list(rids)),
        gc.DataTuple('$MULTICAST_NODE_L1_XID_VALID', bool_arr_val=[0] * len(rids)),
        gc.DataTuple('$MULTICAST_NODE_L1_XID', int_arr_val=[0] * len(rids))
    ])
    mgid_table.entry_mod(target, [mgid_key], [mgid_data])


def make_port(pipe, local_port):
    return (pipe << 7) | local_port


def disable_pktgen(target, bfrt_info, app_id):
    pktgen_app_cfg_table = bfrt_info.table_get("app_cfg")
    mode = "trigger_timer_periodic"

    pktgen_app_cfg_table.entry_mod(
                target,
                [pktgen_app_cfg_table.make_key([gc.KeyTuple('app_id', app_id)])],
                [pktgen_app_cfg_table.make_data([gc.DataTuple('app_enable', bool_val=False)], 
                mode)])
    
    
def configure_pktgen(target, bfrt_info, 
                     app_id, pktgen_pipe, pipe_local_port, pkt, buff_offset, ns):
    pktgen_app_cfg_table = bfrt_info.table_get("app_cfg")
    pktgen_pkt_buffer_table = bfrt_info.table_get("pkt_buffer")
    pktgen_port_cfg_table = bfrt_info.table_get("port_cfg")

    timer_ns = ns
    nb_batch = 1
    nb_pkt = 1
    ibg = 0
    ipg = 0
    mode = "trigger_timer_periodic"

    src_port = make_port(pktgen_pipe, pipe_local_port)
    pkt_len = len(pkt)

    pktgen_app_cfg_table.entry_mod(
                target,
                [pktgen_app_cfg_table.make_key([gc.KeyTuple('app_id', app_id)])],
                [pktgen_app_cfg_table.make_data([gc.DataTuple('app_enable', bool_val=False)], 
                mode)])
    pktgen_port_cfg_table.entry_mod(
                    target,
                    [pktgen_port_cfg_table.make_key([gc.KeyTuple('dev_port', src_port)])],
                    [pktgen_port_cfg_table.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])])
    data = pktgen_app_cfg_table.make_data([gc.DataTuple('timer_nanosec', timer_ns),
                                                        gc.DataTuple('app_enable', bool_val=False),
                                                        gc.DataTuple('pkt_len', (pkt_len - 6)),
                                                        gc.DataTuple('pkt_buffer_offset', buff_offset),
                                                        gc.DataTuple('pipe_local_source_port', pipe_local_port),
                                                        gc.DataTuple('increment_source_port', bool_val=False),
                                                        gc.DataTuple('batch_count_cfg', nb_batch),
                                                        gc.DataTuple('packets_per_batch_cfg', nb_pkt),
                                                        gc.DataTuple('ibg', ibg),
                                                        gc.DataTuple('ibg_jitter', 0),
                                                        gc.DataTuple('ipg', ipg),
                                                        gc.DataTuple('ipg_jitter', 0),
                                                        gc.DataTuple('batch_counter', 0),
                                                        gc.DataTuple('pkt_counter', 0),
                                                        gc.DataTuple('trigger_counter', 0),
                                                        gc.DataTuple('assigned_chnl_id', pipe_local_port)],
                                                        mode)
    pktgen_app_cfg_table.entry_mod(
                    target,
                    [pktgen_app_cfg_table.make_key([gc.KeyTuple('app_id', app_id)])],
                    [data])
    pktgen_pkt_buffer_table.entry_mod(
                    target,
                    [pktgen_pkt_buffer_table.make_key([gc.KeyTuple('pkt_buffer_offset', buff_offset),
                                                    gc.KeyTuple('pkt_buffer_size', (pkt_len - 6))])],
                    [pktgen_pkt_buffer_table.make_data([gc.DataTuple('buffer', bytearray(bytes(pkt)[6:]))])])
    pktgen_app_cfg_table.entry_mod(
                    target,
                    [pktgen_app_cfg_table.make_key([gc.KeyTuple('app_id', app_id)])],
                    [pktgen_app_cfg_table.make_data([gc.DataTuple('app_enable', bool_val=True)], mode)]
                )
