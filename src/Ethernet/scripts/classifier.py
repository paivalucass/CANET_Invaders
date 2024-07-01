from Ethernet.detection.dataset import EthernetDetector
from pcapfile import savefile
import pandas as pd
#currently using CAN detector module
from CAN_Invaders.detection.detector import Detector


c = EthernetDetector('/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/siren_benign/siren_delay/siren_delay.csv', '/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/siren_benign/siren_delay/delay.pcapng')

c.open_pcap()

df = c.label(type='delay', mono=True)

d = Detector(model="IsolationForest")

d.classify(dataset_train=df, label='Malicious', drop=['Malicious','Time','Channel0','Channel_0_difference'], verbose=True, input_dataframe=True)

