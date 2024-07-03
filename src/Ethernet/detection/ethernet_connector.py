from scapy.all import Ether, IP, sendp, hexdump, rdpcap, Raw, sniff
import numpy as np

# This module uses scapy to send and receive packets
# Some of these methods may need admin permission (run using sudo)
class Ethernet:
    def __init__(self, pcap_file=None, interface="eth0"):
        self.pcap_file = pcap_file
        self.interface = interface
        self.last_timestamp = 0
        self.last_channel0 = 0
        self.last_channel1 = 0
        
    def send(self, packet):
        sendp(packet, iface=self.interface)
        
    def receive(self, time_diff=False, channel_diff=False, channel=False):
        features = []
        packet = sniff(iface=self.interface, count=1)
        packet = packet[0]
        channel_0 = []
        channel_1 = []
        if (packet[Raw].load).hex()[0:2] != '02':
            return None
        
        if not time_diff and not channel_diff and not channel:
            return None
        
        if time_diff:
            Time_difference = packet.time - self.last_timestamp
            features.append(Time_difference)
            self.last_timestamp = packet.time
        
        if channel_diff or channel:
            stream_data_lenght = int((packet[Raw].load).hex()[40:44], 16)
            data_full = (packet[Raw].load).hex()[48:]        
                
            data_both_channels = [int(data_full[i:i+2], 16) for i in range(0, len(data_full), 2)]
            diff = len(data_both_channels) - stream_data_lenght
            for i in range(0, len(data_both_channels) - diff, 4):  
                
                sample_channel_0 = (data_both_channels[i] << 8) | data_both_channels[i + 1]
                sample_channel_1 = (data_both_channels[i + 2] << 8) | data_both_channels[i + 3]
                
                channel_0.append(sample_channel_0)
                channel_1.append(sample_channel_1)
            
            channel_0 = np.array(channel_0)
            channel_1 = np.array(channel_1)
            mean_channel0 = np.mean(channel_0)
            mean_channel1 = np.mean(channel_1)
            
            if channel:
                features.append(mean_channel0)
                features.append(mean_channel1)
        
        if channel_diff:
            channel0_difference = mean_channel0 - self.last_channel0
            channel1_difference = mean_channel1 - self.last_channel1
            
            features.append(channel0_difference)
            features.append(channel1_difference)
        
            self.last_channel0 = mean_channel0
            self.last_channel1 = mean_channel1

        return np.array(features)
    
    def replay(self):
        print("Opening pcap file...")
        packets = rdpcap(self.pcap_file)
        print("Sending packets...")
        while True:
            for packet in packets:
                sendp(packet, iface=self.interface)
    
    def listen(self):
        sniff(iface=self.interface, prn=lambda x: x.show())