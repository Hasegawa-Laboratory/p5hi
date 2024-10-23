TofinoIngressParser() tofino_parser;

state start {
    tofino_parser.apply(packet, ig_intr_md);
    transition parse_ethernet;
}

state parse_ethernet {
    packet.extract(hdr.ethernet);
    transition parse_ipv4;
}

state parse_ipv4 {
    packet.extract(hdr.ipv4);
    transition select_packet_type;
}

state select_packet_type {
    transition select(hdr.ipv4.protocol, ig_intr_md.ingress_port) {
        (200, _): parse_phi_header;
        (_, 24): parse_meta;
        (_, 32): parse_meta;
        (_, 40): parse_meta;
        (_, 48): parse_meta;
        (_, 152): parse_meta;
        (_, 160): parse_meta;
        (_, 168): parse_meta;
        (_, 176): parse_meta;
        (_, 280): parse_meta;
        (_, 288): parse_meta;
        (_, 296): parse_meta;
        (_, 304): parse_meta;
        (_, 408): parse_meta;
        (_, 416): parse_meta;
        (_, 424): parse_meta;
        (_, 432): parse_meta;
        default: accept;
    }
}

state parse_phi_header {
    packet.extract(hdr.phi);
    transition parse_phi_handshake;
}

state parse_phi_handshake {
    
    transition select(hdr.phi.mode, hdr.phi.handshake_phase, hdr.phi.recirculated) {
        (2w0, 2w0, 4w0) : parse_phi_stack_forward;
        (2w0, 2w0, 4w4) : parse_phi_stack_forward;
        
        (2w1, 2w0, 4w0) : parse_phi_stack_backward;
        (2w1, 2w0, 4w4) : parse_phi_stack_backward;

        (2w3, 2w0, 4w0) : parse_phi_stack_forward;
        (2w3, 2w0, 4w1) : parse_phi_stack_forward;
        (2w3, 2w0, 4w2) : parse_phi_stack_forward;
        (2w3, 2w0, 4w3) : parse_phi_stack_backward;
        (2w3, 2w0, 4w4) : parse_phi_stack_backward;
        
        (2w3, 2w1, 4w0) : parse_phi_stack_backward;
        (2w3, 2w1, 4w1) : parse_phi_stack_backward;
        (2w3, 2w1, 4w2) : parse_phi_stack_backward;
        (2w3, 2w1, 4w3) : parse_phi_stack_forward;
        (2w3, 2w1, 4w4) : parse_phi_stack_forward;
        
        (2w3, 2w2, 4w0) : parse_phi_stack_forward;
        (2w3, 2w2, 4w1) : parse_phi_stack_forward;
        (2w3, 2w2, 4w2) : parse_phi_stack_forward;
        (2w3, 2w2, 4w3) : parse_phi_stack_backward;
        (2w3, 2w2, 4w4) : parse_phi_stack_backward;

        (2w3, 2w3, 4w0) : parse_phi_stack_backward;
        (2w3, 2w3, 4w4) : parse_phi_stack_backward;
        default: reject;
    }
}

state parse_phi_stack_forward {
    packet.extract(hdr.phi_stack_body);
    packet.extract(hdr.phi_stack_bottom);
    transition before_parse_meta;
}

state parse_phi_stack_backward {
    packet.extract(hdr.phi_stack_top);
    packet.extract(hdr.phi_stack_body);
    transition before_parse_meta;
}

state before_parse_meta {
    transition select(hdr.phi.recirculated) {
        4w1: parse_meta;
        4w2: parse_meta;
        4w3: parse_meta;
        4w4: parse_meta;
        default: accept;
    }
}

state parse_meta {
    packet.extract(hdr.meta);
    transition accept;
}
