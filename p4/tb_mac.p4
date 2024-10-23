action push_mac() {
    hdr.phi_stack_top.mac_a = hdr.meta.mac_a;
    hdr.phi_stack_top.mac_b = hdr.meta.mac_b;
}

action check_mac_top() {
    hdr.meta.mac_a = hdr.meta.mac_a ^ hdr.phi_stack_top.mac_a;
    hdr.meta.mac_b = hdr.meta.mac_b ^ hdr.phi_stack_top.mac_b;
}

action check_mac_bottom() {
    hdr.meta.mac_a = hdr.meta.mac_a ^ hdr.phi_stack_bottom.mac_a;
    hdr.meta.mac_b = hdr.meta.mac_b ^ hdr.phi_stack_bottom.mac_b;
}

table tb_mac {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
    }
    actions = {
        NoAction;
        push_mac;
        check_mac_top;
        check_mac_bottom;
    }
    const size = 8;
    const default_action = NoAction();
    const entries = {
        (2w0, 2w0) : check_mac_top();
        (2w1, 2w0) : check_mac_bottom();
        (2w3, 2w0) : push_mac();
        (2w3, 2w1) : check_mac_bottom();
        (2w3, 2w2) : push_mac();
        (2w3, 2w3) : check_mac_bottom();
    }
}



table tb_mac_helper_to_midway {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
        hdr.meta.is_midway: ternary;
    }
    actions = {
        NoAction;
        check_mac_top;
        check_mac_bottom;
    }
    const size = 4;
    const default_action = NoAction();
    const entries = {
        (2w3, 2w1, 32w0x0) : check_mac_bottom();
        (2w3, 2w1, _) : check_mac_top();
    }
}