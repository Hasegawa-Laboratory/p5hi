
action sr1_st0() {
    hdr.meta.v1_0 = hdr.meta.v1_0 + hdr.meta.v1_1;
    hdr.meta.v1_2 = hdr.meta.v1_2 + hdr.meta.v1_3;

    meta.tmp1_0 = hdr.meta.v1_1[63:32] >> (32 - 13);
    hdr.meta.v1_1 = hdr.meta.v1_1 << 13;

    meta.tmp1_1 = hdr.meta.v1_3[63:32] >> (32 - 16);
    hdr.meta.v1_3 = hdr.meta.v1_3 << 16;
}

action sr1_st1() {
    hdr.meta.v1_1[31:0] = hdr.meta.v1_1[31:0] | meta.tmp1_0;
    hdr.meta.v1_3[31:0] = hdr.meta.v1_3[31:0] | meta.tmp1_1;
}

action sr1_st2() {
    hdr.meta.v1_1 = hdr.meta.v1_1 ^ hdr.meta.v1_0;
    hdr.meta.v1_3 = hdr.meta.v1_3 ^ hdr.meta.v1_2;

    bit<32> tmp;
    tmp = hdr.meta.v1_0[63:32];
    hdr.meta.v1_0[63:32] = hdr.meta.v1_0[31:0];
    hdr.meta.v1_0[31:0] = tmp;
}

action sr1_st3() {
    hdr.meta.v1_2 = hdr.meta.v1_2 + hdr.meta.v1_1;
    hdr.meta.v1_0 = hdr.meta.v1_0 + hdr.meta.v1_3;

    meta.tmp1_0 = hdr.meta.v1_1[63:32] >> (32 - 17);
    hdr.meta.v1_1 = hdr.meta.v1_1 << 17;

    meta.tmp1_1 = hdr.meta.v1_3[63:32] >> (32 - 21);
    hdr.meta.v1_3 = hdr.meta.v1_3 << 21;
}

action sr1_st4() {
    hdr.meta.v1_1[31:0] = hdr.meta.v1_1[31:0] | meta.tmp1_0;
    hdr.meta.v1_3[31:0] = hdr.meta.v1_3[31:0] | meta.tmp1_1;
}

action sr1_st5() {
    hdr.meta.v1_3 = hdr.meta.v1_3 ^ hdr.meta.v1_0;
    hdr.meta.v1_1 = hdr.meta.v1_1 ^ hdr.meta.v1_2;

    bit<32> tmp;
    tmp = hdr.meta.v1_2[63:32];
    hdr.meta.v1_2[63:32] = hdr.meta.v1_2[31:0];
    hdr.meta.v1_2[31:0] = tmp;
}


#define SIPROUND_AUTH() sr1_st0(); sr1_st1(); sr1_st2(); sr1_st3(); sr1_st4(); sr1_st5()
