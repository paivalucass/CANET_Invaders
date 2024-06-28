from Ethernet.detection.ethernet_detector import EthernetDetector
from pcapfile import savefile
c = EthernetDetector('/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/siren_benign/siren_drop/siren_drop.csv', '/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/siren_benign/siren_drop/drop.pcapng')

c.open_pcap()