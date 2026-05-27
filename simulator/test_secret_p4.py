#!/usr/bin/env python3
"""
Teste automático do trabalho P4 "secret".

O programa envia 3 pacotes:
1) TOKEN_INSCRIBE: grava o token no switch. Esperado: pacote é dropado.
2) NORMAL_MSG com token correto. Esperado: pacote passa.
3) NORMAL_MSG com token errado. Esperado: pacote é dropado.

Uso básico:
    sudo python3 test_secret_p4.py --iface veth16

Com captura automática em uma interface de saída:
    sudo python3 test_secret_p4.py --iface veth16 --sniff-iface veth18

Se não souber a interface:
    python3 test_secret_p4.py --list-ifaces
"""

import argparse
import sys
import time
from typing import Optional

try:
    from scapy.all import Ether, Raw, sendp, sniff, get_if_list
except ImportError:
    print("ERRO: Scapy não está instalado.")
    print("Instale com: sudo apt install python3-scapy")
    print("ou: pip3 install scapy")
    sys.exit(1)


ETHERTYPE_SECRET = 0x1234

# Conforme headers.p4:
# #define NORMAL_MSG 1
# #define TOKEN_INSCRIBE 2
NORMAL_MSG = 1
TOKEN_INSCRIBE = 2

DEFAULT_SRC_MAC = "00:00:00:00:00:01"
DEFAULT_DST_MAC = "00:00:00:00:00:02"

# O header secret_t no headers.p4 está nesta ordem:
# bit<128> token;
# bit<8>   msg_type;
TOKEN_CORRETO = bytes.fromhex("00112233445566778899aabbccddeeff")

# Sua implementação atual compara principalmente os 32 bits finais token[31:0].
# Então o token errado precisa terminar diferente de cc dd ee ff.
TOKEN_ERRADO = bytes.fromhex("00112233445566778899aabb00000000")


def montar_pacote(dst_mac: str, src_mac: str, token: bytes, msg_type: int, texto: str):
    if len(token) != 16:
        raise ValueError("O token precisa ter exatamente 16 bytes, pois no P4 ele é bit<128>.")

    secret_header = token + bytes([msg_type])
    payload = texto.encode("utf-8")

    return Ether(dst=dst_mac, src=src_mac, type=ETHERTYPE_SECRET) / Raw(secret_header + payload)


def enviar(nome: str, pkt, iface: str, intervalo: float):
    print(f"\n=== {nome} ===")
    print(f"Enviando pela interface: {iface}")
    print(f"Resumo: {pkt.summary()}")
    print("Bytes:")
    print(bytes(pkt).hex(" "))

    sendp(pkt, iface=iface, verbose=False)
    print("Pacote enviado.")
    time.sleep(intervalo)


def capturar(sniff_iface: str, timeout: float):
    print(f"\n[CAPTURA] Escutando {sniff_iface} por {timeout:.1f}s...")
    pkts = sniff(
        iface=sniff_iface,
        timeout=timeout,
        lfilter=lambda p: Ether in p and p[Ether].type == ETHERTYPE_SECRET,
    )

    print(f"[CAPTURA] Pacotes EtherType 0x{ETHERTYPE_SECRET:04x} vistos: {len(pkts)}")

    for i, p in enumerate(pkts, start=1):
        raw = bytes(p)
        print(f"\n--- Capturado #{i} ---")
        print(p.summary())
        print(raw.hex(" "))

        # Ethernet = 14 bytes; secret = 17 bytes; payload vem depois
        if len(raw) >= 14 + 17:
            token = raw[14:30]
            msg_type = raw[30]
            payload = raw[31:]
            print(f"token: {token.hex()}")
            print(f"msg_type: {msg_type}")
            try:
                print(f"payload: {payload.decode('utf-8', errors='replace')}")
            except Exception:
                print(f"payload bytes: {payload.hex(' ')}")

    return pkts


def main():
    parser = argparse.ArgumentParser(description="Teste automático para o P4 secret.")
    parser.add_argument("--iface", default="veth16", help="Interface usada para enviar pacotes. Padrão: veth16.")
    parser.add_argument("--sniff-iface", default=None, help="Interface para capturar pacotes encaminhados. Ex.: veth18.")
    parser.add_argument("--src-mac", default=DEFAULT_SRC_MAC, help=f"MAC origem. Padrão: {DEFAULT_SRC_MAC}.")
    parser.add_argument("--dst-mac", default=DEFAULT_DST_MAC, help=f"MAC destino. Padrão: {DEFAULT_DST_MAC}.")
    parser.add_argument("--intervalo", type=float, default=1.0, help="Intervalo entre envios. Padrão: 1s.")
    parser.add_argument("--sniff-timeout", type=float, default=3.0, help="Tempo de captura após os envios. Padrão: 3s.")
    parser.add_argument("--list-ifaces", action="store_true", help="Lista interfaces disponíveis e sai.")
    args = parser.parse_args()

    if args.list_ifaces:
        print("Interfaces disponíveis:")
        for iface in get_if_list():
            print(f"  {iface}")
        return

    print("==============================================")
    print("TESTE DO P4 SECRET")
    print("==============================================")
    print(f"EtherType usado: 0x{ETHERTYPE_SECRET:04x}")
    print(f"NORMAL_MSG: {NORMAL_MSG}")
    print(f"TOKEN_INSCRIBE: {TOKEN_INSCRIBE}")
    print(f"MAC origem: {args.src_mac}")
    print(f"MAC destino: {args.dst_mac}")
    print(f"Interface de envio: {args.iface}")
    print(f"Interface de captura: {args.sniff_iface if args.sniff_iface else '(não usada)'}")
    print("")
    print("Ordem esperada no pacote:")
    print("Ethernet / token de 16 bytes / msg_type de 1 byte / payload")
    print("")
    print("Resultado esperado:")
    print("1) TOKEN_INSCRIBE: grava token e deve ser dropado.")
    print("2) NORMAL_MSG com token correto: deve passar.")
    print("3) NORMAL_MSG com token errado: deve dropar.")
    print("")

    pkt_gravar = montar_pacote(
        dst_mac=args.dst_mac,
        src_mac=args.src_mac,
        token=TOKEN_CORRETO,
        msg_type=TOKEN_INSCRIBE,
        texto="TESTE_1_GRAVA_TOKEN_DEVE_DROPAR",
    )

    pkt_correto = montar_pacote(
        dst_mac=args.dst_mac,
        src_mac=args.src_mac,
        token=TOKEN_CORRETO,
        msg_type=NORMAL_MSG,
        texto="TESTE_2_TOKEN_CORRETO_DEVE_PASSAR",
    )

    pkt_errado = montar_pacote(
        dst_mac=args.dst_mac,
        src_mac=args.src_mac,
        token=TOKEN_ERRADO,
        msg_type=NORMAL_MSG,
        texto="TESTE_3_TOKEN_ERRADO_DEVE_DROPAR",
    )

    enviar("TESTE 1: gravar token", pkt_gravar, args.iface, args.intervalo)
    enviar("TESTE 2: mensagem com token correto", pkt_correto, args.iface, args.intervalo)
    enviar("TESTE 3: mensagem com token errado", pkt_errado, args.iface, args.intervalo)

    if args.sniff_iface:
        print("\nATENÇÃO: esta captura acontece após os envios.")
        print("Para uma validação mais forte, também deixe um tcpdump rodando em outro painel durante os envios.")
        capturar(args.sniff_iface, args.sniff_timeout)

    print("\n==============================================")
    print("FIM DOS TESTES")
    print("==============================================")
    print("Validação esperada no tcpdump da porta de saída:")
    print("- NÃO deve aparecer TESTE_1_GRAVA_TOKEN_DEVE_DROPAR")
    print("- DEVE aparecer TESTE_2_TOKEN_CORRETO_DEVE_PASSAR")
    print("- NÃO deve aparecer TESTE_3_TOKEN_ERRADO_DEVE_DROPAR")
    print("")
    print("Comando sugerido em outro painel:")
    print(f"sudo tcpdump -i <interface_saida> ether proto 0x{ETHERTYPE_SECRET:04x} -XX -vv")


if __name__ == "__main__":
    main()
