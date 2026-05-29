#!/usr/bin/env python3
import sys
from scapy.all import Ether, Packet, ByteField, BitField, bind_layers, sendp

SET_TOKEN_TYPE = 0
MSG_TOKEN_TYPE = 1

class SecretHeader(Packet):
    name = "SecretHeader"
    fields_desc = [
        ByteField("msg_type", 1),       # 1 byte para o tipo da mensagem (Ex:0=Gravar Token, 1=Msg normal)
        BitField("token", 0, 128)       # 16 bytes (128 bits) para o Token Secreto
    ]

ETHERTYPE_SECRET = 0x1234
bind_layers(Ether, SecretHeader, type=ETHERTYPE_SECRET)


def enviar():

    #### SET TOKEN PACKET ########################################################
    # O objetivo desta mensagem é escrever a chave nos registradores do switch

    interface_origem = "veth0"
    mac_origem = "00:00:00:00:00:01" # veth0
    interface_destino = "veth16"
    mac_destino = "00:00:00:00:00:03"  # veth16
    
    print(f"Enviando da {interface_origem} para {interface_destino}")
    print("Pacote do tipo SET TOKEN")

    token_16bytes = 0x11223344556677889900AABBCCDDEEFF 
    pkt = (
        Ether(src=mac_origem, dst=mac_destino, type=ETHERTYPE_SECRET) /
        SecretHeader(msg_type=SET_TOKEN_TYPE, token=token_16bytes) /
        "Escrevendo TOKEN no switch"
    )

    # Exibe a estrutura do pacote montado no terminal antes de enviar
    print("Estrutura do pacote a ser enviado:")
    pkt.show()

    # Envia o pacote na camada 2 (Data Link) através da veth0
    sendp(pkt, iface=interface_origem, verbose=False)
    print(f"\nPacote enviado com sucesso!")

    ##############################################################################
    #### MSG WITH WRONG TOKEN ####################################################
    # Esta mensagem deve ser dropada pelo switch

    print(f"Enviando da {interface_origem} para {interface_destino}")
    print("Pacote do tipo TOKEN MSG")

    token_16bytes = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    pkt = (
        Ether(src=mac_origem, dst=mac_destino, type=ETHERTYPE_SECRET) /
        SecretHeader(msg_type=MSG_TOKEN_TYPE, token=token_16bytes) /
        "Esta mensagem contém o TOKEN errado"
    )

    print("Estrutura do pacote a ser enviado:")
    pkt.show()

    sendp(pkt, iface=interface_origem, verbose=False)
    print(f"\nPacote enviado com sucesso!")

    ##############################################################################
    #### MSG WITH RIGHT TOKEN ####################################################
    # Esta mensagem deve passar pelo switch

    print(f"Enviando da {interface_origem} para {interface_destino}")
    print("Pacote do tipo TOKEN MSG")

    token_16bytes = 0x11223344556677889900AABBCCDDEEFF
    pkt = (
        Ether(src=mac_origem, dst=mac_destino, type=ETHERTYPE_SECRET) /
        SecretHeader(msg_type=MSG_TOKEN_TYPE, token=token_16bytes) /
        "Esta mensagem contém o TOKEN certo"
    )

    print("Estrutura do pacote a ser enviado:")
    pkt.show()

    sendp(pkt, iface=interface_origem, verbose=False)
    print(f"\nPacote enviado com sucesso!")


if __name__ == "__main__":
    enviar()