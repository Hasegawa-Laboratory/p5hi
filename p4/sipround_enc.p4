
action sr0_st0() {
    hdr.meta.v0_0 = hdr.meta.v0_0 + hdr.meta.v0_1;
    hdr.meta.v0_2 = hdr.meta.v0_2 + hdr.meta.v0_3;

    meta.tmp0_0 = hdr.meta.v0_1[63:32] >> (32 - 13);
    hdr.meta.v0_1 = hdr.meta.v0_1 << 13;

    meta.tmp0_1 = hdr.meta.v0_3[63:32] >> (32 - 16);
    hdr.meta.v0_3 = hdr.meta.v0_3 << 16;
}

action sr0_st1() {
    hdr.meta.v0_1[31:0] = hdr.meta.v0_1[31:0] | meta.tmp0_0;
    hdr.meta.v0_3[31:0] = hdr.meta.v0_3[31:0] | meta.tmp0_1;
}

action sr0_st2() {
    hdr.meta.v0_1 = hdr.meta.v0_1 ^ hdr.meta.v0_0;
    hdr.meta.v0_3 = hdr.meta.v0_3 ^ hdr.meta.v0_2;

    bit<32> tmp;
    tmp = hdr.meta.v0_0[63:32];
    hdr.meta.v0_0[63:32] = hdr.meta.v0_0[31:0];
    hdr.meta.v0_0[31:0] = tmp;
}

action sr0_st3() {
    hdr.meta.v0_2 = hdr.meta.v0_2 + hdr.meta.v0_1;
    hdr.meta.v0_0 = hdr.meta.v0_0 + hdr.meta.v0_3;

    meta.tmp0_0 = hdr.meta.v0_1[63:32] >> (32 - 17);
    hdr.meta.v0_1 = hdr.meta.v0_1 << 17;

    meta.tmp0_1 = hdr.meta.v0_3[63:32] >> (32 - 21);
    hdr.meta.v0_3 = hdr.meta.v0_3 << 21;
}

action sr0_st4() {
    hdr.meta.v0_1[31:0] = hdr.meta.v0_1[31:0] | meta.tmp0_0;
    hdr.meta.v0_3[31:0] = hdr.meta.v0_3[31:0] | meta.tmp0_1;
}

action sr0_st5() {
    hdr.meta.v0_3 = hdr.meta.v0_3 ^ hdr.meta.v0_0;
    hdr.meta.v0_1 = hdr.meta.v0_1 ^ hdr.meta.v0_2;

    bit<32> tmp;
    tmp = hdr.meta.v0_2[63:32];
    hdr.meta.v0_2[63:32] = hdr.meta.v0_2[31:0];
    hdr.meta.v0_2[31:0] = tmp;
}


#define SIPROUND_ENC() sr0_st0(); sr0_st1(); sr0_st2(); sr0_st3(); sr0_st4(); sr0_st5()
