
action set_recirculation_port(port_id_t port) {
    hdr.meta.recirculation_port = port;
}

table tb_set_recirculation_port {
    key = {
        hdr.ipv4.protocol: ternary;
        hdr.phi.mode: ternary;
        hdr.phi.handshake_phase: ternary;
        hdr.meta.recirculation_random: ternary;
        hdr.phi.plain_dst: ternary;
    }
    actions = {
        set_recirculation_port;
    }
    const size = 256;
}



action set_forwarding_port(bit<9> egress_port, bit<32> next_addr) {
    hdr.meta.egress_port = (bit<16>)egress_port;
    hdr.meta.next_addr = next_addr;
}

action drop() {
    ig_dprsr_md.drop_ctl = 7; 
}

table tb_forwarding {
    key = {
        hdr.phi.plain_dst: lpm;
    }
    actions = {
        drop;
        set_forwarding_port;
    }
    const size = FIB_SIZE;
    const default_action = drop();
}



action forward(bit<9> egress_port) {
    ig_tm_md.ucast_egress_port = egress_port;
}

table tb_forwarding_ap {
    key = {
        hdr.ipv4.dst_addr: lpm;
    }
    actions = {
        drop;
        forward;
    }
    const size = FIB_SIZE_AP;
    const default_action = drop();
}



action recirculate() {
    ig_tm_md.ucast_egress_port = hdr.meta.recirculation_port;
}

action forward_immediately() {
    ig_tm_md.ucast_egress_port = hdr.meta.egress_port[8:0];
    ig_tm_md.bypass_egress = 1w1;
    hdr.phi.recirculated = 0;

#ifndef OUT_META
    hdr.meta.setInvalid();
#endif
}

action add_handshake_phase() {
	hdr.phi.handshake_phase = 2w2;
    ig_tm_md.ucast_egress_port = hdr.meta.recirculation_port;
}

table tb_drop {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
        hdr.meta.is_midway: ternary;
        hdr.meta.mac_a: ternary;
        hdr.meta.mac_b: ternary;
    }
    actions = {
        NoAction;
        recirculate;
        forward_immediately;
        add_handshake_phase;
        drop;
    }
    const size = 4;
    const default_action = recirculate();
    const entries = {
        (2w3, 2w1, 32w0x0 &&& 32w0xFFFFFFFF, 32w0 &&& 32w0xFFFFFFFF, 32w0 &&& 32w0xFFFFFFFF) : forward_immediately();
        (2w3, 2w1, 32w0x0 &&& 32w0xFFFFFFFF, _, _) : drop();
        (2w3, 2w1, _, 32w0 &&& 32w0xFFFFFFFF, 32w0 &&& 32w0xFFFFFFFF) : add_handshake_phase();
        (2w3, 2w1, _, _, _) : drop();
    }
}



table tb_distribute_out
{
    key = {
        ig_tm_md.ucast_egress_port: exact;
        hdr.meta.recirculation_random[6:5]: exact;
    }
    actions = {
        NoAction;
        forward;
    }
    const size = 32;
    const default_action = NoAction();
}