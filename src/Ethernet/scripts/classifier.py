from Ethernet.detection.ethernet_detector import EthernetDetector
from pcapfile import savefile
c = EthernetDetector('/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/delay_pink_floyd/delay_pink_floyd.csv', '/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/delay_pink_floyd/TSNBox_192.168.41.151_4455.pcapng')

c.open_pcap()