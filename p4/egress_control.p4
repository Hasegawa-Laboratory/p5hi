#include "sipround_enc.p4"
#include "sipround_auth.p4"

#include "tb_mac.p4"

// Finalize hash for MAC
action calc_mac_a() {
	@in_hash { hdr.meta.mac_a = hdr.meta.v1_0[63:32] ^ hdr.meta.v1_2[63:32]; }
}

action calc_mac_b() {
    @in_hash{ hdr.meta.mac_b = hdr.meta.v1_0[31:0] ^ hdr.meta.v1_2[31:0]; }
}



action drop() {
    eg_dprsr_md.drop_ctl = 7; 
}

table tb_drop {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
        hdr.meta.mac_a: ternary;
        hdr.meta.mac_b: ternary;
    }
    actions = {
        drop;
        NoAction;
    }
    const size = 8;
    const default_action = NoAction();
    const entries = {
        (2w0, 2w0, 32w0 &&& 32w0xFFFFFFFF, 32w0 &&& 32w0xFFFFFFFF) : NoAction();
        (2w0, 2w0, _, _) : drop();
        (2w1, 2w0, 32w0 &&& 32w0xFFFFFFFF, 32w0 &&& 32w0xFFFFFFFF) : NoAction();
        (2w1, 2w0, _, _) : drop();
        (2w3, 2w1, 32w0 &&& 32w0xFFFFFFFF, 32w0 &&& 32w0xFFFFFFFF) : NoAction();
        (2w3, 2w1, _, _) : drop();
        (2w3, 2w3, 32w0 &&& 32w0xFFFFFFFF, 32w0 &&& 32w0xFFFFFFFF) : NoAction();
        (2w3, 2w3, _, _) : drop();
    }
}



action set_recir_1(){
	hdr.phi.recirculated = 4w1;
}

action set_recir_4(){
	hdr.phi.recirculated = 4w4;
}

table tb_set_recirculated {
    key = {
        hdr.phi.mode: exact;
        hdr.phi.handshake_phase: exact;
        hdr.phi.recirculated: exact;
    }
    actions = {
        set_recir_1;
        set_recir_4;
        NoAction;
    }
    const size = 16;
    const default_action = NoAction();
    const entries = {
        (2w0, 2w0, 4w0) : set_recir_4();
        (2w1, 2w0, 4w0) : set_recir_4();
        (2w3, 2w0, 4w0) : set_recir_1();
        (2w3, 2w0, 4w3) : set_recir_4();
        (2w3, 2w1, 4w0) : set_recir_1();
        (2w3, 2w1, 4w3) : set_recir_4();
        (2w3, 2w2, 4w0) : set_recir_1();
        (2w3, 2w2, 4w3) : set_recir_4();
        (2w3, 2w3, 4w0) : set_recir_4();
    }
}

apply {
	if (hdr.phi.recirculated == 4w0 || hdr.phi.recirculated == 4w3) {
		hdr.meta.v1_3[63:32] = hdr.meta.v1_3[63:32] ^ hdr.meta.m_0a;
        hdr.meta.v1_3[31:0] = hdr.meta.v1_3[31:0] ^ hdr.meta.m_0b;
        	
		SIPROUND_ENC();
		SIPROUND_AUTH();
        	
		SIPROUND_ENC();
		SIPROUND_AUTH();
		
		hdr.meta.v1_0[63:32] = hdr.meta.v1_0[63:32] ^ hdr.meta.m_0a;
        hdr.meta.v1_0[31:0] = hdr.meta.v1_0[31:0] ^ hdr.meta.m_0b;
        hdr.meta.v1_3[63:32] = hdr.meta.v1_3[63:32] ^ hdr.meta.nonce_a;
        hdr.meta.v1_3[31:0] = hdr.meta.v1_3[31:0] ^ hdr.meta.nonce_b;
        	
		SIPROUND_ENC();
		sr1_st0(); sr1_st1(); sr1_st2(); sr1_st3(); sr1_st4();  // Partial execution of SIPROUND_AUTH
		
		tb_set_recirculated.apply();

    } else if (hdr.phi.recirculated == 4w1){
		sr1_st5();  // Partial execution of SIPROUND_AUTH
		SIPROUND_AUTH();
        	
        hdr.meta.v1_0[63:32] = hdr.meta.v1_0[63:32] ^ hdr.meta.nonce_a;
        hdr.meta.v1_0[31:0] = hdr.meta.v1_0[31:0] ^ hdr.meta.nonce_b;
        hdr.meta.v1_2[31:0] = hdr.meta.v1_2[31:0] ^ 0xFF;
        	
		SIPROUND_AUTH();
		sr1_st0(); sr1_st1(); sr1_st2(); sr1_st3(); sr1_st4();  // Partial execution of SIPROUND_AUTH
		
        hdr.phi.recirculated = 4w2;
    
    } else if (hdr.phi.recirculated == 4w2) {

        hdr.phi.recirculated = 4w3;

    } else if (hdr.phi.recirculated == 4w4) {
		sr1_st5();  // Partial execution of SIPROUND_AUTH
		SIPROUND_AUTH();
		SIPROUND_AUTH();
		
		// Finalize
		hdr.meta.v1_0[63:32] = hdr.meta.v1_0[63:32] ^ hdr.meta.v1_1[63:32];
		hdr.meta.v1_0[31:0] = hdr.meta.v1_0[31:0] ^ hdr.meta.v1_1[31:0];
        hdr.meta.v1_2[63:32] = hdr.meta.v1_2[63:32] ^ hdr.meta.v1_3[63:32];
        hdr.meta.v1_2[31:0] = hdr.meta.v1_2[31:0] ^ hdr.meta.v1_3[31:0];
        calc_mac_a();
        calc_mac_b();

		tb_mac.apply();
		tb_drop.apply();
		
        hdr.phi.recirculated = 4w0;

    #ifndef OUT_META
        hdr.meta.setInvalid();
    #endif
	}
}
