Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_0;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_1;

action decrypt_src_backward_stack() {
    hdr.phi_stack_top.src_addr = hdr.phi_stack_top.src_addr ^ copy32_0.get(meta.otp_a);
}

action decrypt_src_forward_stack() {
    hdr.phi_stack_bottom.src_addr = hdr.phi_stack_bottom.src_addr ^ copy32_0.get(meta.otp_a);
}

table tb_decrypt_src {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
    }
    actions = {
        NoAction;
        decrypt_src_forward_stack;
        decrypt_src_backward_stack;
    }
    const size = 8;
    const default_action = NoAction();
    const entries = {
        (2w0, 2w0) : decrypt_src_forward_stack();
        (2w1, 2w0) : decrypt_src_backward_stack();
        (2w3, 2w0) : NoAction();
        (2w3, 2w1) : decrypt_src_backward_stack();
        (2w3, 2w2) : NoAction();
        (2w3, 2w3) : decrypt_src_backward_stack();
    }
}



action decrypt_dst_backward_stack() {
    hdr.phi_stack_top.dst_addr = hdr.phi_stack_top.dst_addr ^ copy32_1.get(meta.otp_b);
}

action decrypt_dst_forward_stack() {
    hdr.phi_stack_bottom.dst_addr = hdr.phi_stack_bottom.dst_addr ^ copy32_1.get(meta.otp_b);
}

table tb_decrypt_dst {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
    }
    actions = {
        NoAction;
        decrypt_dst_forward_stack;
        decrypt_dst_backward_stack;
    }
    const size = 8;
    const default_action = NoAction();
    const entries = {
        (2w0, 2w0) : decrypt_dst_forward_stack();
        (2w1, 2w0) : decrypt_dst_backward_stack();
        (2w3, 2w0) : NoAction();
        (2w3, 2w1) : decrypt_dst_backward_stack();
        (2w3, 2w2) : NoAction();
        (2w3, 2w3) : decrypt_dst_backward_stack();
    }
}

