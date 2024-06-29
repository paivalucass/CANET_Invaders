import pandas as pd
from scapy.all import rdpcap, Raw
from scapy.utils import RawPcapNgReader
import sounddevice as sd
import numpy as np


class EthernetDetector:
    def __init__(self, csv_file, pcap_file=None):
        self.csv_file = csv_file
        self.pcap_file = pcap_file
        self.csv_modified = csv_file.split('.csv')[0] + '_modified.csv'
        self.csv_labeled = csv_file.split('.csv')[0] + '_labeled.csv'

    def open_csv(self):
        df = pd.read_csv(self.csv_file, header=0, dtype={'Time': float, 'Source': str, 'Destination': str, 'Protocol': str, 'Length': int, 'Info': str})
        filtered_df = df.loc[df['Protocol'] == 'IEEE1722'].copy()
        filtered_df['Time_Difference'] = filtered_df['Time'].diff()
        path = self.csv_file.split('.csv')[0] + '_time_diff.csv'
        filtered_df.to_csv(path, index=False)
        
    def label(self, mono=False, type='drop'):
        df = pd.read_csv(self.csv_modified, header=0, dtype={'Time': float, 'Source': str, 'Destination': str, 'Protocol': str, 'Length': int, 'Info': str, 'Time_Difference': float, 'channel0': float, 'channel1': float, 'Channel_0_difference': float, 'Channel_1_difference': float})
        if mono:
            df = df.drop(['Channel1', 'Channel_1_difference','No.','Source', 'Destination', 'Protocol', 'Length', 'Info'], axis=1)
        else:
            df = df.drop(['No.','Source', 'Destination', 'Protocol', 'Length', 'Info'], axis=1)

        times = np.array([])
        for time in df['Time_Difference']:
            times = np.append(times, time)
        
        time_mean = np.mean(times)
        
        # label the data
        if type == 'drop':
            df['Malicious'] = df['Time_Difference'].apply(lambda time: '-1' if time >= time_mean*1.5 else '1')
        elif type == 'delay':
            df['Malicious'] = df['Time_Difference'].apply(lambda time: '-1' if time >= time_mean*1.5 or time <= time_mean*0.8 else '1')
        elif type == 'noise':
            df['Malicious'] = df['Time_Difference'].apply(lambda time: '-1' if time >= time_mean*1.5 or time <= time_mean*0.8 else '1')
        elif type == 'oos':
            df['Malicious'] = 0
            for i in range(0, len(df)):
                if i == 0:
                    continue
                if mono:
                    if (df.loc[i, 'Channel_0_difference'] < 0 and df.loc[i-1, 'Channel_0_difference'] > 0 and df.loc[i+1, 'Channel_0_difference'] > 0) or (df.loc[i, 'Channel_0_difference'] > 0 and df.loc[i-1, 'Channel_0_difference'] < 0 and df.loc[i+1, 'Channel_0_difference'] < 0): 
                        if abs(df.loc[i, 'Channel_0_difference']) > 20*df.loc[i-1, 'Channel_0_difference'] or abs(df.loc[i, 'Channel_1_difference']) > 20*df.loc[i-1, 'Channel_1_difference']:
                            df.loc[i, 'Malicious'] = 1
                        else:
                            df.loc[i, 'Malicious'] = -1
                    else:
                        df.loc[i, 'Malicious'] = 1
                else:
                    if (df.loc[i, 'Channel_0_difference'] < 0 and df.loc[i-1, 'Channel_0_difference'] > 0 and df.loc[i+1, 'Channel_0_difference'] > 0) or (df.loc[i, 'Channel_0_difference'] > 0 and df.loc[i-1, 'Channel_0_difference'] < 0 and df.loc[i+1, 'Channel_0_difference'] < 0) or (df.loc[i, 'Channel_1_difference'] < 0 and df.loc[i-1, 'Channel_1_difference'] > 0 and df.loc[i+1, 'Channel_1_difference'] > 0) or (df.loc[i, 'Channel_1_difference'] > 0 and df.loc[i-1, 'Channel_1_difference'] < 0 and df.loc[i+1, 'Channel_1_difference'] < 0):
                        df.loc[i, 'Malicious'] = -1
                    else:
                        df.loc[i, 'Malicious'] = 1
                df['Malicious'] = df['Time_Difference'].apply(lambda time: '-1' if time >= time_mean*1.5 or time <= time_mean*0.8 else '1')


        path = self.csv_labeled
        
        df.to_csv(path, index=False)
        
    # def detect(self, mono=False, type='drop'):
    
    
    
    def open_pcap(self, play_audio=False, save_audio=True):
        print("Opening pcap file...")
        packets = rdpcap(self.pcap_file)
        data_channel_0 = []
        data_channel_1 = []
        audio = bytearray()
        
        print("Processing packets...")
        for packet in packets:
            if Raw in packet:
                channel_0 = []
                channel_1 = []
                
                sample_bytes = []
                
                if (packet[Raw].load).hex()[0:2] != '02':
                    continue
                # get paylod lenght from the frame information
                stream_data_lenght = int((packet[Raw].load).hex()[40:44], 16)
                data_full = (packet[Raw].load).hex()[48:]        
                
                # extract audio sample                
                audio_hex = (packet[Raw].load.hex()[48:48+(stream_data_lenght*2)])   
                sample_bytes = bytearray.fromhex(audio_hex)              
                audio.extend(sample_bytes)
                
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
                data_channel_0.append(mean_channel0)
                data_channel_1.append(mean_channel1)
            

        df = pd.read_csv(self.csv_file, header=0, dtype={'Time': float, 'Source': str, 'Destination': str, 'Protocol': str, 'Length': int, 'Info': str})
        filtered_df = df.loc[df['Protocol'] == 'IEEE1722'].copy()
        # calculating time difference between packets
        filtered_df['Time_Difference'] = filtered_df['Time'].diff()
        filtered_df = filtered_df.assign(Channel0=data_channel_0, Channel1=data_channel_1)
        # calculating difference between samples values
        filtered_df['Channel_0_difference'] = filtered_df['Channel0'].diff()
        filtered_df['Channel_1_difference'] = filtered_df['Channel1'].diff()
        
        filtered_df = filtered_df.dropna()
        
        path = self.csv_modified
        filtered_df.to_csv(path, index=False)
       
        if save_audio:
            import wave
            print("Saving audio...")
            with wave.open('audio.wav', 'wb') as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(48000)
                wf.writeframes(audio)     
                  
        if play_audio:
            import pyaudio
            
            p = pyaudio.PyAudio()
            print("Playing audio...")
            sample_width = 2
            audio_format = p.get_format_from_width(sample_width)
            stream = p.open(format=audio_format, channels=1, rate=48000, output=True)
            
            audio_bytes = bytes(audio)
            stream.write(audio_bytes)
            stream.stop_stream()
            stream.close()
            p.terminate()