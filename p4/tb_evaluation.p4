
action set_phase(bit<2> mode, bit<2> phase, bit<32> midway) {
    hdr.phi.mode = mode;
    hdr.phi.handshake_phase = phase;
    hdr.meta.is_midway = midway;
}


table tb_set_phase {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
        hdr.meta.recirculation_random: ternary;
    }
    actions = {
        drop;
        set_phase;
    }
    const default_action = drop();
    const size = 16;
}


action modify_addr(bit<32> ip_dst) {
    hdr.phi.plain_dst = ip_dst;
}

action modify_addr_and_top(bit<32> ip_dst, bit<192> stack_entry) {
    hdr.phi.plain_dst = ip_dst;
    hdr.phi_stack_top.src_addr = stack_entry[191:160];
    hdr.phi_stack_top.dst_addr = stack_entry[159:128];
    hdr.phi_stack_top.nonce_a = stack_entry[127:96];
    hdr.phi_stack_top.nonce_b = stack_entry[95:64];
    hdr.phi_stack_top.mac_a = stack_entry[63:32];
    hdr.phi_stack_top.mac_b = stack_entry[31:0];
}

action modify_addr_and_bottom(bit<32> ip_dst, bit<192> stack_entry) {
    hdr.phi.plain_dst = ip_dst;
    hdr.phi_stack_bottom.src_addr = stack_entry[191:160];
    hdr.phi_stack_bottom.dst_addr = stack_entry[159:128];
    hdr.phi_stack_bottom.nonce_a = stack_entry[127:96];
    hdr.phi_stack_bottom.nonce_b = stack_entry[95:64];
    hdr.phi_stack_bottom.mac_a = stack_entry[63:32];
    hdr.phi_stack_bottom.mac_b = stack_entry[31:0];
}

table tb_modify {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
        hdr.meta.is_midway[0:0]: ternary;
        hdr.meta.recirculation_random: ternary;
    }
    actions = {
        drop;
        modify_addr;
        modify_addr_and_top;
        modify_addr_and_bottom;
    }
    const default_action = drop();
    const size = 64;
}

