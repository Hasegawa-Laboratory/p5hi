#include "sipround_enc.p4"
#include "sipround_auth.p4"

#include "tb_mac.p4"
#include "tb_addr.p4"
#include "tb_decrypt.p4"
#include "tb_stack_encrypt.p4"
#include "tb_forwarding.p4"
#include "tb_evaluation.p4"

Random<bit<32>>() random32_0;
Random<bit<32>>() random32_1;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_4;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_5;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_6;
Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy32_7;
Random<bit<7>>() random7_0;


// Get nonces
action initialize_new_nonce_a() {
    hdr.meta.nonce_a = random32_0.get();
}

action initialize_existing_nonce_a_top() {
	hdr.meta.nonce_a = hdr.phi_stack_top.nonce_a;
}

action initialize_existing_nonce_a_bottom() {
	hdr.meta.nonce_a = hdr.phi_stack_bottom.nonce_a;
}

table tb_initialize_nonce_a {
    key = {
        hdr.phi.recirculated: exact;
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
    }
    actions = {
        NoAction;
        initialize_new_nonce_a;
        initialize_existing_nonce_a_top;
        initialize_existing_nonce_a_bottom;
    }
    const size = 8;
    const default_action = NoAction();
    const entries = {
        (4w0, 2w0, 2w0) : initialize_existing_nonce_a_bottom();
        (4w0, 2w1, 2w0) : initialize_existing_nonce_a_top();
        (4w0, 2w3, 2w0) : initialize_new_nonce_a();
        (4w0, 2w3, 2w1) : initialize_existing_nonce_a_top();
        (4w0, 2w3, 2w2) : initialize_new_nonce_a();
        (4w0, 2w3, 2w3) : initialize_existing_nonce_a_top();
    }
}



action initialize_new_nonce_b() {
    hdr.meta.nonce_b = random32_1.get();
}

action initialize_existing_nonce_b_top() {
	hdr.meta.nonce_b = hdr.phi_stack_top.nonce_b;
}

action initialize_existing_nonce_b_bottom() {
	hdr.meta.nonce_b = hdr.phi_stack_bottom.nonce_b;
}

table tb_initialize_nonce_b {
    key = {
        hdr.phi.recirculated: exact;
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
    }
    actions = {
        NoAction;
        initialize_new_nonce_b;
        initialize_existing_nonce_b_top;
        initialize_existing_nonce_b_bottom;
    }
    const size = 8;
    const default_action = NoAction();
    const entries = {
        (4w0, 2w0, 2w0) : initialize_existing_nonce_b_bottom();
        (4w0, 2w1, 2w0) : initialize_existing_nonce_b_top();
        (4w0, 2w3, 2w0) : initialize_new_nonce_b();
        (4w0, 2w3, 2w1) : initialize_existing_nonce_b_top();
        (4w0, 2w3, 2w2) : initialize_new_nonce_b();
        (4w0, 2w3, 2w3) : initialize_existing_nonce_b_top();
    }
}



// Initialize internal states of SipHash
action initialize_v(
    bit<64> init_0_0, bit<64> init_0_1, bit<64> init_0_2, bit<64> init_0_3, 
    bit<64> init_1_0, bit<64> init_1_1, bit<64> init_1_2, bit<64> init_1_3) {

    hdr.meta.v0_0 = init_0_0;
    hdr.meta.v0_1 = init_0_1;
    hdr.meta.v0_2 = init_0_2;
    hdr.meta.v0_3 = init_0_3;
    
    hdr.meta.v1_0 = init_1_0;
    hdr.meta.v1_1 = init_1_1;
    hdr.meta.v1_2 = init_1_2;
    hdr.meta.v1_3 = init_1_3;
}

table tb_initialize {
    key = {
        hdr.phi.mode: exact;    // dummy
    }
    actions = {
        initialize_v;
    }
    const size = 4;
}



action initialize_v1(bit<64> init_1_0, bit<64> init_1_1, bit<64> init_1_2, bit<64> init_1_3) {
    hdr.meta.v1_0 = init_1_0;
    hdr.meta.v1_1 = init_1_1;
    hdr.meta.v1_2 = init_1_2;
    hdr.meta.v1_3 = init_1_3;
}

table tb_reinitialize {
    key = {
        hdr.phi.mode: exact;    // dummy
    }
    actions = {
        initialize_v1;
    }
    const size = 4;
}



// Input nonces to the SipHash processes
action initialize_nonce_a() {
    hdr.meta.v0_3[63:32] = hdr.meta.v0_3[63:32] ^ copy32_4.get(hdr.meta.nonce_a);
}

action initialize_nonce_b() {
    hdr.meta.v0_3[31:0] = hdr.meta.v0_3[31:0] ^ copy32_5.get(hdr.meta.nonce_b);
}

action initialize_previous_mac_a() {
    hdr.meta.v1_3[63:32] = hdr.meta.v1_3[63:32] ^ copy32_6.get(hdr.phi_stack_body.mac_a);
}

action initialize_previous_mac_b() {
    hdr.meta.v1_3[31:0] = hdr.meta.v1_3[31:0] ^ copy32_7.get(hdr.phi_stack_body.mac_b);
}

action xor_v0_0a_nonce_a() {
	hdr.meta.v0_0[63:32] = hdr.meta.v0_0[63:32] ^ copy32_4.get(hdr.meta.nonce_a);
}

action xor_v0_0b_nonce_b() {
    hdr.meta.v0_0[31:0] = hdr.meta.v0_0[31:0] ^ copy32_5.get(hdr.meta.nonce_b);
}

action xor_v1_0a_previous_mac_a() {
	hdr.meta.v1_0[63:32] = hdr.meta.v1_0[63:32] ^ copy32_6.get(hdr.phi_stack_body.mac_a);
}

action xor_v1_0b_previous_mac_b() {
    hdr.meta.v1_0[31:0] = hdr.meta.v1_0[31:0] ^ copy32_7.get(hdr.phi_stack_body.mac_b);
}



action xor_v1_0a_nonce_a() {
	hdr.meta.v1_0[63:32] = hdr.meta.v1_0[63:32] ^ copy32_4.get(hdr.meta.nonce_a);
}

action xor_v1_0b_nonce_b() {
    hdr.meta.v1_0[31:0] = hdr.meta.v1_0[31:0] ^ copy32_5.get(hdr.meta.nonce_b);
}


// Finalize pad for encryption
action calc_otp_a() {
	@in_hash { meta.otp_a = hdr.meta.v0_0[63:32] ^ hdr.meta.v0_2[63:32]; }
}

action calc_otp_b() {
	@in_hash { meta.otp_b = hdr.meta.v0_0[31:0] ^ hdr.meta.v0_2[31:0]; }
}


// Finalize hash value for MAC
action calc_mac_a() {
	@in_hash { hdr.meta.mac_a = hdr.meta.v1_0[63:32] ^ hdr.meta.v1_2[63:32]; }
}

action calc_mac_b() {
	@in_hash { hdr.meta.mac_b = hdr.meta.v1_0[31:0] ^ hdr.meta.v1_2[31:0]; }
}



apply {

    
    if (ig_intr_md.ingress_port[6:0] == 56 || ig_intr_md.ingress_port[6:0] == 64) { 
        drop();

    } else if (hdr.ipv4.protocol != 200 && hdr.meta.isValid() == false) {
		hdr.meta.setValid();
		hdr.phi.setValid();

        hdr.meta.recirculation_random = random7_0.get();
        tb_set_recirculation_port.apply();

        ig_tm_md.ucast_egress_port = hdr.meta.recirculation_port;
        ig_tm_md.bypass_egress = 1w1;
        hdr.phi.setInvalid();
    
    } else if (hdr.ipv4.protocol != 200 && hdr.meta.isValid() == true) {
		hdr.phi.setValid();

        hdr.phi.plain_dst = hdr.ipv4.dst_addr;
        tb_forwarding.apply();

        ig_tm_md.ucast_egress_port = hdr.meta.egress_port[8:0];

        ig_tm_md.bypass_egress = 1w1;
        hdr.phi.setInvalid();
        
    #ifndef OUT_META
        hdr.meta.setInvalid();
    #endif
    
    } else if (hdr.phi.recirculated == 4w0) {
       	hdr.meta.setValid();

		tb_initialize_nonce_a.apply();
		tb_initialize_nonce_b.apply();
        hdr.meta.recirculation_random = random7_0.get();
        	
		tb_initialize.apply();
        initialize_nonce_a();
        initialize_nonce_b();
		
        initialize_previous_mac_a();
        initialize_previous_mac_b();
        
		SIPROUND_ENC();
		SIPROUND_AUTH();

		SIPROUND_ENC();
		SIPROUND_AUTH();
		
		xor_v0_0a_nonce_a();
        xor_v0_0b_nonce_b();
        
        xor_v1_0a_previous_mac_a();
        xor_v1_0b_previous_mac_b();

        hdr.meta.v0_2[31:0] = hdr.meta.v0_2[31:0] ^ 0xFF;
        	
		tb_get_addr.apply();
        tb_set_recirculation_port.apply();

        ig_tm_md.ucast_egress_port = hdr.meta.recirculation_port;
    
    } else if (hdr.phi.recirculated == 4w1){
        tb_forwarding.apply();

        ig_tm_md.ucast_egress_port = hdr.meta.recirculation_port;
        	
    } else if (hdr.phi.recirculated == 4w2){
		sr1_st5();  // Partial execution of SIPROUND_AUTH
		SIPROUND_ENC();
		SIPROUND_AUTH();
		
		hdr.meta.v0_0[63:32] = hdr.meta.v0_0[63:32] ^ hdr.meta.v0_1[63:32];
		hdr.meta.v0_0[31:0] = hdr.meta.v0_0[31:0] ^ hdr.meta.v0_1[31:0];
        hdr.meta.v0_2[63:32] = hdr.meta.v0_2[63:32] ^ hdr.meta.v0_3[63:32];
        hdr.meta.v0_2[31:0] = hdr.meta.v0_2[31:0] ^ hdr.meta.v0_3[31:0];
        calc_otp_a();
        calc_otp_b();
        	
		SIPROUND_AUTH();
		hdr.meta.v1_0[63:32] = hdr.meta.v1_0[63:32] ^ hdr.meta.v1_1[63:32];
		hdr.meta.v1_0[31:0] = hdr.meta.v1_0[31:0] ^ hdr.meta.v1_1[31:0];
        hdr.meta.v1_2[63:32] = hdr.meta.v1_2[63:32] ^ hdr.meta.v1_3[63:32];
        hdr.meta.v1_2[31:0] = hdr.meta.v1_2[31:0] ^ hdr.meta.v1_3[31:0];
        calc_mac_a();
        calc_mac_b();
		
		tb_decrypt_src.apply();
		tb_decrypt_dst.apply();
		tb_set_addr.apply();
		tb_stack_encrypt_src.apply();
		tb_stack_encrypt_dst.apply();
		
		tb_mac_helper_to_midway.apply();
		tb_drop.apply();
		
		
		tb_myaddr.apply();
		hdr.ipv4.dst_addr = hdr.meta.next_addr;

    } else if (hdr.phi.recirculated == 4w3) {

        tb_reinitialize.apply();
        
        initialize_previous_mac_a();
        initialize_previous_mac_b();

		SIPROUND_AUTH();
		SIPROUND_AUTH();

        xor_v1_0a_previous_mac_a();
        xor_v1_0b_previous_mac_b();

		tb_get_addr.apply();
        
        ig_tm_md.ucast_egress_port = hdr.meta.recirculation_port;
    		
	} else if (hdr.phi.recirculated == 4w4 && (hdr.phi.mode != 2w3 || hdr.phi.handshake_phase == 2w3)) {
		sr1_st5();  // Partial execution of SIPROUND_AUTH
		SIPROUND_ENC();
		SIPROUND_AUTH();
		
		hdr.meta.v0_0[63:32] = hdr.meta.v0_0[63:32] ^ hdr.meta.v0_1[63:32];
		hdr.meta.v0_0[31:0] = hdr.meta.v0_0[31:0] ^ hdr.meta.v0_1[31:0];
        hdr.meta.v0_2[63:32] = hdr.meta.v0_2[63:32] ^ hdr.meta.v0_3[63:32];
        hdr.meta.v0_2[31:0] = hdr.meta.v0_2[31:0] ^ hdr.meta.v0_3[31:0];
        calc_otp_a();
        calc_otp_b();
        	
        xor_v1_0a_nonce_a();
        xor_v1_0b_nonce_b();
        hdr.meta.v1_2[31:0] = hdr.meta.v1_2[31:0] ^ 0xFF;
        	
		SIPROUND_AUTH();
		
		tb_decrypt_src.apply();
		tb_decrypt_dst.apply();
		tb_set_addr.apply();
		tb_stack_encrypt_src.apply();
		tb_stack_encrypt_dst.apply();

		sr1_st0(); sr1_st1(); sr1_st2(); sr1_st3(); sr1_st4();  // Partial execution of SIPROUND_AUTH
		
		tb_myaddr.apply();
		hdr.ipv4.dst_addr = hdr.meta.next_addr;
        tb_forwarding_ap.apply();

            
	} else if (hdr.phi.recirculated == 4w4){
		sr1_st5();  // Partial execution of SIPROUND_AUTH
		SIPROUND_AUTH();
		
        xor_v1_0a_nonce_a();
        xor_v1_0b_nonce_b();
        hdr.meta.v1_2[31:0] = hdr.meta.v1_2[31:0] ^ 0xFF;
        	
		SIPROUND_AUTH();
		sr1_st0(); sr1_st1(); sr1_st2(); sr1_st3(); sr1_st4();  // Partial execution of SIPROUND_AUTH

		ig_tm_md.ucast_egress_port = hdr.meta.egress_port[8:0];
	}

    tb_distribute_out.apply();
}
