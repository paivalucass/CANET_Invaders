from Ethernet.detection.ethernet_detector import EthernetDetector
from pcapfile import savefile


c = EthernetDetector('/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/siren_benign/siren_oos/siren_oos.csv', '/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/siren_benign/siren_oos/out_of_sequence.pcapng')

c.open_pcap()

c.label(type='oos', mono=True)