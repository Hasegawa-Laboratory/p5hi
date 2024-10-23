Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_20;

action get_addr_top() {
    hdr.meta.m_0a = hdr.phi_stack_top.src_addr;
    hdr.meta.m_0b = hdr.phi_stack_top.dst_addr;
}

action get_addr_bottom() {
    hdr.meta.m_0a = hdr.phi_stack_bottom.src_addr;
    hdr.meta.m_0b = hdr.phi_stack_bottom.dst_addr;
}

table tb_get_addr {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
        hdr.meta.is_midway: ternary;
    }
    actions = {
        NoAction;
        get_addr_top;
        get_addr_bottom;
    }
    const size = 8;
    const default_action = NoAction();
    const entries = {
        (2w0, 2w0, _) : get_addr_bottom();
        (2w1, 2w0, _) : get_addr_top();
        (2w3, 2w0, _) : get_addr_top();
        (2w3, 2w1, 32w0x0 &&& 32w0xFFFFFFFF) : get_addr_bottom();
        (2w3, 2w1, _) : get_addr_top();
        (2w3, 2w2, _) : get_addr_top();
        (2w3, 2w3, _) : get_addr_top();
    }
}



action check_midway() {
    hdr.meta.is_midway = hdr.phi_stack_top.src_addr ^ hdr.meta.next_addr;
}

action set_port_from_stack_backward() {
    hdr.meta.next_addr = hdr.phi_stack_top.src_addr;
}

action set_port_from_stack_forward() {
    hdr.meta.next_addr = copy32_20.get(hdr.phi_stack_bottom.dst_addr);
}

table tb_set_addr {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
    }
    actions = {
        NoAction;
        set_port_from_stack_backward;
        set_port_from_stack_forward;
        check_midway;
    }
    const size = 8;
    const default_action = NoAction();
    const entries = {
        (2w0, 2w0) : set_port_from_stack_forward();
        (2w1, 2w0) : set_port_from_stack_backward();
        (2w3, 2w3) : set_port_from_stack_backward();
        (2w3, 2w0) : check_midway();
        (2w3, 2w1) : check_midway();
        (2w3, 2w2) : check_midway();
    }
}



action set_myaddr(bit<32> myaddr) {
    hdr.ipv4.src_addr = myaddr;
}

table tb_myaddr {
    key = {
        hdr.phi.mode: exact;    // dummy
    }
    size = 4;
    actions = {
        set_myaddr;
    }
}
