Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_2;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_3;

action stack_rot_bw_src() {
    hdr.phi_stack_top.setInvalid();
    hdr.phi_stack_bottom.setValid();
    hdr.phi_stack_bottom.src_addr = hdr.phi_stack_top.src_addr ^ copy32_2.get(meta.otp_a);
}

action stack_rot_fw_src() {
    hdr.phi_stack_bottom.setInvalid();
    hdr.phi_stack_top.setValid();
    hdr.phi_stack_top.src_addr = hdr.phi_stack_bottom.src_addr ^ copy32_2.get(meta.otp_a);
}

action stack_push_src() {
    hdr.phi_stack_bottom.setInvalid();
    hdr.phi_stack_top.setValid();
    hdr.phi_stack_top.src_addr = hdr.ipv4.src_addr ^ copy32_2.get(meta.otp_a);
}

action stack_revise_src() {
    hdr.phi_stack_top.src_addr = hdr.phi_stack_top.src_addr ^ copy32_2.get(meta.otp_a);
}

table tb_stack_encrypt_src {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
        hdr.meta.is_midway: ternary;
    }
    actions = {
        NoAction;
        stack_rot_fw_src;
        stack_rot_bw_src;
        stack_push_src;
        stack_revise_src;
    }
    const size = 8;
    const default_action = NoAction();
    const entries = {
        (2w0, 2w0, _) : stack_rot_fw_src();
        (2w1, 2w0, _) : stack_rot_bw_src();
        (2w3, 2w0, _) : stack_push_src();
        (2w3, 2w1, 32w0x0 &&& 32w0xFFFFFFFF) : stack_rot_bw_src();
        (2w3, 2w1, _) : stack_revise_src();
        (2w3, 2w2, _) : stack_push_src();
        (2w3, 2w3, _) : stack_rot_bw_src();
    }
}



action stack_rot_bw_dst() {
    hdr.phi_stack_bottom.dst_addr = hdr.phi_stack_top.dst_addr ^ copy32_3.get(meta.otp_b);
    hdr.phi_stack_bottom.mac_a = hdr.phi_stack_top.mac_a;
    hdr.phi_stack_bottom.mac_b = hdr.phi_stack_top.mac_b;
    hdr.phi_stack_bottom.nonce_a = hdr.meta.nonce_a;
    hdr.phi_stack_bottom.nonce_b = hdr.meta.nonce_b;
}

action stack_rot_fw_dst() {
    hdr.phi_stack_top.dst_addr = hdr.phi_stack_bottom.dst_addr ^ copy32_3.get(meta.otp_b);
    hdr.phi_stack_top.mac_a = hdr.phi_stack_bottom.mac_a;
    hdr.phi_stack_top.mac_b = hdr.phi_stack_bottom.mac_b;
    hdr.phi_stack_top.nonce_a = hdr.meta.nonce_a;
    hdr.phi_stack_top.nonce_b = hdr.meta.nonce_b;
}

action stack_push_dst() {
    hdr.phi_stack_top.dst_addr = hdr.meta.next_addr ^ copy32_3.get(meta.otp_b);
    hdr.phi_stack_top.nonce_a = hdr.meta.nonce_a;
    hdr.phi_stack_top.nonce_b = hdr.meta.nonce_b;
}

action stack_revise_dst() {
    hdr.phi_stack_top.dst_addr = hdr.meta.next_addr ^ copy32_3.get(meta.otp_b);
}

table tb_stack_encrypt_dst {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
        hdr.meta.is_midway: ternary;
    }
    actions = {
        NoAction;
        stack_rot_fw_dst;
        stack_rot_bw_dst;
        stack_push_dst;
        stack_revise_dst;
    }
    const size = 8;
    const default_action = NoAction();
    const entries = {
        (2w0, 2w0, _) : stack_rot_fw_dst();
        (2w1, 2w0, _) : stack_rot_bw_dst();
        (2w3, 2w0, _) : stack_push_dst();
        (2w3, 2w1, 32w0x0 &&& 32w0xFFFFFFFF) : stack_rot_bw_dst();
        (2w3, 2w1, _) : stack_revise_dst();
        (2w3, 2w2, _) : stack_push_dst();
        (2w3, 2w3, _) : stack_rot_bw_dst();
    }
}
