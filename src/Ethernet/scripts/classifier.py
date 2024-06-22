from Ethernet.detection.ethernet_detector import EthernetDetector
from pcapfile import savefile
# c = EthernetDetector('/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/benigno_pink_floyd/TSNBox_192.168.41.151_4455.pcapng')

# c.detect()

with open('/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/benigno_pink_floyd/TSNBox_192.168.41.151_4455.pcapng', 'rb') as file:
    pcap = savefile.load_savefile(file, verbose=True)
    print(pcap)