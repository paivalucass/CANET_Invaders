from scapy.all import Ether, IP, sendp

# Define os campos do pacote Ethernet
eth = Ether(dst="00:11:22:33:44:55", src="00:11:22:33:44:66")  # Endereços MAC de destino e origem

# Define os campos do pacote IP
ip = IP(dst="192.168.1.100")  # Endereço IP de destino

# Cria o pacote combinado
packet = eth / ip

packet.show()  # Mostra o pacote criado

# Envia o pacote pela interface de rede
sendp(packet, iface="eth0")