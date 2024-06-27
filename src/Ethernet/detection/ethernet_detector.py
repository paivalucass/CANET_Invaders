import pandas as pd
from scapy.all import rdpcap, Raw
import sounddevice as sd
import numpy as np



class EthernetDetector:
    def __init__(self, csv_file, pcap_file=None):
        self.csv_file = csv_file
        self.pcap_file = pcap_file

    def open_csv(self):
        df = pd.read_csv(self.csv_file, header=0, dtype={'Time': float, 'Source': str, 'Destination': str, 'Protocol': str, 'Length': int, 'Info': str})
        filtered_df = df.loc[df['Protocol'] == 'IEEE1722'].copy()
        filtered_df['Time_Difference'] = filtered_df['Time'].diff()
        path = self.csv_file.split('.csv')[0] + '_time_diff.csv'
        filtered_df.to_csv(path, index=False)
        
    def open_pcap(self, play_audio=True, save_audio=True):
        print("Opening pcap file...")
        packets = rdpcap(self.pcap_file)
        data_channel_0 = []
        data_channel_1 = []
        audio = bytearray()
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
                # print(stream_data_lenght)
                data_full = (packet[Raw].load).hex()[48:]
                
                
                # extract audio sample
                audio_hex = (packet[Raw].load.hex()[48:48+(stream_data_lenght*2)]) 
                print("length of audio_hex: ", len(audio_hex))   
                # print(audio_hex)         
                sample_bytes = bytearray.fromhex(audio_hex)    
                # print(sample_bytes)            
                audio.extend(sample_bytes)
                
                
                data_both_channels = [int(data_full[i:i+2], 16) for i in range(0, len(data_full), 2)]
                diff = len(data_both_channels) - stream_data_lenght
                for i in range(0, len(data_both_channels) - diff):
                    if i % 2 == 0:
                        channel_0.append(data_both_channels[i])
                    else:
                        channel_1.append(data_both_channels[i])
                print(channel_0)
                print(channel_1)
                channel_0 = np.array(channel_0)
                channel_1 = np.array(channel_1)
                mean_channel0 = np.mean(channel_0)
                mean_channel1 = np.mean(channel_1)
                data_channel_0.append(mean_channel0)
                data_channel_1.append(mean_channel1)
            
        print(len(data_channel_0))
        print(len(data_channel_1))

        df = pd.read_csv(self.csv_file, header=0, dtype={'Time': float, 'Source': str, 'Destination': str, 'Protocol': str, 'Length': int, 'Info': str})
        filtered_df = df.loc[df['Protocol'] == 'IEEE1722'].copy()
        filtered_df['Time_Difference'] = filtered_df['Time'].diff()
        filtered_df = filtered_df.assign(channel0=data_channel_0, channel1=data_channel_1)
        filtered_df = filtered_df.dropna()
        path = self.csv_file.split('.csv')[0] + '_modified.csv'
        filtered_df.to_csv(path, index=False)
       
        if save_audio:
            import wave
            print("Saving audio...")
            with wave.open('audio.wav', 'wb') as wf:
                wf.setnchannels(2)
                wf.setsampwidth(2)
                wf.setframerate(48000)
                wf.writeframes(audio)     
                  
        if play_audio:
            import pyaudio
            
            p = pyaudio.PyAudio()
            print("Playing audio...")
            sample_width = 2
            audio_format = p.get_format_from_width(sample_width)
            stream = p.open(format=audio_format, channels=2, rate=48000, output=True)
            
            audio_bytes = bytes(audio)
            stream.write(audio_bytes)
            stream.stop_stream()
            stream.close()
            p.terminate()