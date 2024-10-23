#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"

// #define OUT_META 1

#define FIB_SIZE 135000
#define FIB_SIZE_AP 10320

#define CONST_0 64w0x736f6d6570736575
#define CONST_1 64w0x646f72616e646f6d
#define CONST_2 64w0x6c7967656e657261
#define CONST_3 64w0x7465646279746573

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86DD;
const bit<8> TYPE_TCP = 0x6;
const bit<4> VERSION_IPV4 = 0x4;
const bit<4> VERSION_IPV6 = 0x6;

const bit<9> RECIRCULATION_PORT0 = 68;
const bit<9> RECIRCULATION_PORT1 = 196;
const bit<9> RECIRCULATION_PORT2 = 324;
const bit<9> RECIRCULATION_PORT3 = 452;

typedef bit<9> port_id_t;

header metadata {
    bit<32> otp_a;
    bit<32> otp_b;

    bit<32> tmp0_0;
    bit<32> tmp0_1;
    bit<32> tmp1_0;
    bit<32> tmp1_1;
}


header phi_h {
    /*
        mode:
        00 -> data transfer, forward
        01 -> data transfer, backward
        11 -> handshake

        handshake_phase:
        00 -> data transfer
        00 -> sender to helper
        01 -> helper to midway
        10 -> midway to receiver
        11 -> receiver to sender
    */
    bit<2> mode;
    bit<2> handshake_phase;
    bit<4> recirculated;
    bit<32> plain_dst;
}

header phi_stack_item_h {
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<32> nonce_a;
    bit<32> nonce_b;
    bit<32> mac_a;
    bit<32> mac_b;
}

header phi_stack_body_h {//12
    bit<64> addrs;
    bit<64> nonce;
    bit<32> mac_a;
    bit<32> mac_b;
    bit<1920> mid_items;
}

header meta_h {
    bit<64> v0_0;
    bit<64> v0_1;
    bit<64> v0_2;
    bit<64> v0_3;

    bit<64> v1_0;
    bit<64> v1_1;
    bit<64> v1_2;
    bit<64> v1_3;
    
    bit<32> m_0a;
    bit<32> m_0b;
    bit<32> mac_a;
    bit<32> mac_b;
    
    bit<32> is_midway;
    bit<7> recirculation_random;
    bit<9> recirculation_port;
    bit<16> egress_port;
    bit<32> next_addr;
    
    bit<32> nonce_a;
    bit<32> nonce_b;
}

struct headers {
    ethernet_h ethernet;
    ipv4_h ipv4;
    phi_h phi;

    phi_stack_item_h phi_stack_top;
    phi_stack_body_h phi_stack_body;
    phi_stack_item_h phi_stack_bottom;

    meta_h meta;
}

#include "p5hi_pipe0.p4"
#include "p5hi_pipe1.p4"
#include "p5hi_pipe2.p4"
#include "p5hi_pipe3.p4"

Switch(pipe0, pipe1, pipe2, pipe3) main;
