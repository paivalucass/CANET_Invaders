from Ethernet.detection.ethernet_connector import Ethernet 

network = Ethernet('/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/siren_benign/siren_delay/delay.pcapng',interface="eth10")


network.replay()