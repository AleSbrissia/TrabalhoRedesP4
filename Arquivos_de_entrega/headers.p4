#ifndef _HEADERS_
    #define _HEADERS_

#include <core.p4>
#include <v1model.p4>

#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

const bit<16> ETHERTYPE_TUNEL_SECRETO = 0x1234;
const bit<8> MSG_TYPE_SET_TOKEN = 0x00;
const bit<8> MSG_TOKEN = 0x01;

typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header msg_type_t {
    // SET_TOKEN = 0 ou MSG_TOKEN = 1
    bit<8> msg_type;
}

header token_t {
    bit<32> part0;
    bit<32> part1;
    bit<32> part2;
    bit<32> part3;
}

struct header_t {
    ethernet_h ethernet;
    msg_type_t type;
    token_t token;
}

// Variáveis metadados auxiliares, caso ache necessário utilizá-las
struct metadata_t {
    bit<32> aux1;
    bit<32> aux2;
    bit<32> aux3;
    bit<32> aux4;
    bit<128> aux5;
}

#endif /* _HEADERS_ */
