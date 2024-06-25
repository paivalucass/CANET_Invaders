import pandas as pd
from scapy.all import rdpcap, Raw


class EthernetDetector:
    def __init__(self, csv_file, pcap_file=None):
        self.csv_file = csv_file
        self.pcap_file = pcap_file

    def open_csv(self):
        df = pd.read_csv(self.csv_file, header=0, dtype={'Time': float, 'Source': str, 'Destination': str, 'Protocol': str, 'Length': int, 'Info': str})
        df['Time_Difference'] = df['Time'].diff()
        path = self.csv_file.split('.csv')[0] + '_time_diff.csv'
        df.to_csv(path, index=False)
        
    def open_pcap(self):
        packets = rdpcap(self.pcap_file)
        data = []
        for packet in packets:
            if Raw in packet:
                channel_0 = []
                channel_1 = []
                print("-----------------------------")
                # print(packet)
                print((packet[Raw].load).hex())
                if (packet[Raw].load).hex()[0:2] != '02':
                    continue
                # get paylod lenght from the frame information
                stream_data_lenght = int((packet[Raw].load).hex()[40:44], 16)
                print(stream_data_lenght)
                data_full = (packet[Raw].load).hex()[48:]
                print(data_full)
                data_both_channels = [int(data_full[i:i+2], 16) for i in range(0, len(data_full), 2)]
                diff = len(data_both_channels) - stream_data_lenght
                for i in range(0, len(data_both_channels) - diff):
                    if i % 2 == 0:
                        channel_0.append(data_both_channels[i])
                    else:
                        channel_1.append(data_both_channels[i])
                print(channel_0)
                print(channel_1)
                # data.append((packet[Raw].load).hex()[48:])
                
                
        # df = pd.read_csv(self.csv_file, header=0, dtype={'Time': float, 'Source': str, 'Destination': str, 'Protocol': str, 'Length': int, 'Info': str})
        # df['Time_Difference'] = df['Time'].diff()
        # df = df.assign(Data=data)
        # path = self.csv_file.split('.csv')[0] + '_time_diff.csv'
        # df.to_csv(path, index=False)
       
        
        
        
        
        # for packet in packets:
        #     df = df.append({'Time': packet.time, 'Source': packet.src, 'Destination': packet.dst, 'Protocol': packet.proto, 'Length': len(packet), 'Info': packet.summary()}, ignore_index=True)
        # df['Time_Difference'] = df['Time'].diff()
        
        # path = pcap_file.split('.pcap')[0] + '_time_diff.csv'
        # df.to_csv(path, index=False)