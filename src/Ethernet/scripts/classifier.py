#!/usr/bin/python3

from Ethernet.detection.dataset import EthernetDetector
#currently using CAN detector module
from CAN.detection.detector import Detector
import argparse
import joblib

argparser = argparse.ArgumentParser(description='Ethernet Detector model creator') 
argparser.add_argument("csv", type=str, help='CSV file path to use for the detector')
argparser.add_argument("pcap", type=str, help='PCAP file path to use for the detector')
argparser.add_argument('-t', '--type', type=str, default="delay", help='Type of attack to detect / available: delay, drop, noise, oos')
argparser.add_argument('-a', '--audio', type=str, default="mono", help='Mono or estereo audio')
argparser.add_argument('-p', '--play', action='store_true', help='Play extracted audio')
argparser.add_argument('-s', '--save', action='store_true', help='Save extracted audio')


args = argparser.parse_args()


c = EthernetDetector(args.csv, args.pcap)

c.open_pcap(play_audio=args.play, save_audio=args.save)

if args.audio == "mono":
    df = c.label(type=args.type, mono=True)
else:
    df = c.label(type=args.type, mono=False)

d = Detector(model="IsolationForest")

model = d.classify(dataset_train=df, label='Malicious', drop=['Malicious','Time','Channel0','Channel_0_difference'], verbose=True, input_dataframe=True)

with open(args.csv.split('.csv')[0] + '_model.pkl', 'wb') as file:
    joblib.dump(model, file)
    
file.close()
    
