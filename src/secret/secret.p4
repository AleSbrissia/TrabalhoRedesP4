#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "parser.p4"


/* ===================================================== Ingress ===================================================== */


control SwitchIngress(
    /* User */
    inout header_t      hdr,
    inout metadata_t    meta,
    /* Intrinsic */
    in ingress_intrinsic_metadata_t                     ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t         ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t     ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t           ig_tm_md)
{
    /* Forward */
    action hit(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action miss(bit<3> drop) {
        ig_dprsr_md.drop_ctl = drop;
    }

    table forward {
        key = {
            hdr.ethernet.dst_addr : exact;
        }

        actions = {
            hit;
            @defaultonly miss;
        }

        const default_action = miss(0x1);
        size = 1024;
    }

    /* 
    Cria um registrador no formato:
        Register <tipo de dado armazenado, tamanho do indexador> (quantas entradas)
    No caso abaixo cria um registrador com uma entrada, indexado por 1 bit e valores de 32 bits.
    DICA: o mesmo registrador não pode ser acessado mais de uma vez por pacote, e armazenam valores
    de no máximo 32 bits, utilize multiplos registradores
    */
    // Register<bit<32>, bit<1>> (1) secret_values;

    Register<bit<32>, bit<1>> (1) token_part0;
    Register<bit<32>, bit<1>> (1) token_part1;
    Register<bit<32>, bit<1>> (1) token_part2;
    Register<bit<32>, bit<1>> (1) token_part3;


    apply {
        /* Realiza roteamento MAC. Não excluir */
        forward.apply();

        if (hdr.ethernet.ether_type == 0x1234) {

            if (hdr.secret.msg_type == TOKEN_INSCRIBE) {
                token_part0.write(0, hdr.secret.token[31:0]);
                token_part1.write(0, hdr.secret.token[63:32]);
                token_part2.write(0, hdr.secret.token[95:64]);
                token_part3.write(0, hdr.secret.token[127:96]);

                ig_dprsr_md.drop_ctl = 1;
            } else {
                if (hdr.secret.msg_type == NORMAL_MSG) {
                    bit<32> saved_p0;
                    bit<32> saved_p1;
                    bit<32> saved_p2;
                    bit<32> saved_p3;

                    saved_p0 = token_part0.read(1w0);
                    saved_p1 = token_part1.read(1w0);
                    saved_p2 = token_part2.read(1w0);
                    saved_p3 = token_part3.read(1w0);

                    //hdr.secret.token[63:32]  == saved_p1 &&
                    //hdr.secret.token[95:64]  == saved_p2 &&
                    //hdr.secret.token[127:96] == saved_p3

                    if (hdr.secret.token[31:0]  == saved_p0) 
                    {
                        // Sucesso
                    } else {
                        ig_dprsr_md.drop_ctl = 1;
                    }
                }

            }
        }

        /*
        Para ler um registrador:
            secret_values.read(index);

        Para escrever:
            secret_values.write(index, value);

        Para dropar um pacote:
            ig_dprsr_md.drop_ctl = 1;
        */
    }
}

/* ===================================================== Egress ===================================================== */

control SwitchEgress(
    /* User */
    inout header_t      hdr,
    inout metadata_t    meta,
    /* Intrinsic */
    in egress_intrinsic_metadata_t                      eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t          eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t      eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t   eg_oport_md)
{
    apply {}
}


/* ===================================================== Final Pipeline ===================================================== */
Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;
