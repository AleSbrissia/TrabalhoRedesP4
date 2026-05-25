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

#define NORMAL_MSG 1
#define TOKEN_INSCRIBE 2

typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header secret_t {
    bit<128> token;
    bit<8> msg_type;
}

struct header_t {
    ethernet_h ethernet;
    secret_t secret;
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
