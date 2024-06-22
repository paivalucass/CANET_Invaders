from pcapfile import savefile

class EthernetDetector:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file

    def detect(self):
        with open(self.pcap_file, 'rb') as file:
            pcap = savefile.load_savefile(file, verbose=True)
            print(pcap)
            # for packet in pcap.packets:
            #     pass