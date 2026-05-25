#!/usr/bin/env python3
import sys
from scapy.all import *

# 1. Definir a estrutura do cabeçalho customizado igual ao P4
class SecretProtocol(Packet):
    name = "SecretProtocol"
    fields_desc = [
        # Um campo de 128 bits (16 bytes) para o token representado em formato bruto
        FieldLenField("token", None, fmt="16s", length_of="token"),
        # Um campo de 8 bits (1 byte) para o tipo da mensagem
        ByteField("msg_type", 1)
    ]

# Forçar o Scapy a entender que quando o EtherType for 0x1234, o próximo bloco é o nosso protocolo
bind_layers(Ether, SecretProtocol, type=0x1234)

# Configurações de constantes
INTERFACE_ENTRADA = "veth0"  # Porta 1/0 do switch
MAC_DESTINO_VALIDO = "00:00:00:00:00:02" # MAC mapeado para a porta 2/0 no setup.py

# Tokens de teste (precisam ter exatamente 16 bytes de comprimento)
TOKEN_CORRETO   = b"SENHA_SECRETA_16"
TOKEN_INCORRETO = b"SENHA_ERRADA_123"

print("=== INICIANDO TESTES DO TÚNEL SECRETO ===")

# -------------------------------------------------------------------------
# PASSO 1: Enviar pacote de Gravação (TOKEN_INSCRIBE = 2)
# -------------------------------------------------------------------------
print("\n[1/3] Enviando pacote de gravação do Token...")
# Monta o frame: Ethernet / Nosso Protocolo / Payload de dados
pkt_inscribe = Ether(dst=MAC_DESTINO_VALIDO, type=0x1234) / SecretProtocol(token=TOKEN_CORRETO, msg_type=2) / "Config"

sendp(pkt_inscribe, iface=INTERFACE_ENTRADA, verbose=False)
print("-> Pacote de gravação enviado. (Deve ser processado e dropado pelo switch).")

# Pequena pausa para o switch processar
time.sleep(1)

# -------------------------------------------------------------------------
# PASSO 2: Enviar mensagem com o Token INCORRETO (NORMAL_MSG = 1)
# -------------------------------------------------------------------------
print("\n[2/3] Enviando mensagem com Token INCORRETO...")
pkt_errado = Ether(dst=MAC_DESTINO_VALIDO, type=0x1234) / SecretProtocol(token=TOKEN_INCORRETO, msg_type=1) / "Mensagem Hacker"

sendp(pkt_errado, iface=INTERFACE_ENTRADA, verbose=False)
print("-> Pacote incorreto enviado. (O tcpdump no Terminal 2 deve continuar em silêncio).")

time.sleep(1)

# -------------------------------------------------------------------------
# PASSO 3: Enviar mensagem com o Token CORRETO (NORMAL_MSG = 1)
# -------------------------------------------------------------------------
print("\n[3/3] Enviando mensagem com Token CORRETO...")
pkt_correto = Ether(dst=MAC_DESTINO_VALIDO, type=0x1234) / SecretProtocol(token=TOKEN_CORRETO, msg_type=1) / "Mensagem Autorizada"

sendp(pkt_correto, iface=INTERFACE_ENTRADA, verbose=False)
print("-> Pacote correto enviado. (Verifique o Terminal 2, a mensagem deve aparecer lá!)")
