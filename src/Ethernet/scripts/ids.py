#!/usr/bin/python3
import joblib
from Ethernet.detection.ethernet_connector import Ethernet 
import argparse

argparser = argparse.ArgumentParser(description='Ethernet Detector model creator') 
argparser.add_argument("pkl", type=str, help='pkl Model file path')
argparser.add_argument('-i', '--interface', type=str, default="eth10", help='Interface to use for the detector')
argparser.add_argument('-t', '--time_diff', action='store_true', help='Use time difference as a feature')
argparser.add_argument('-d', '--channel_diff', action='store_true', help='Use channel difference as a feature')
argparser.add_argument('-c', '--channel', action='store_true', help='Use channel value as a feature')
argparser.add_argument('-a', '--avtp', action='store_true', help='Use AVTP timestamp as a feature')
args = argparser.parse_args()

network = Ethernet(interface=args.interface)

with open(args.pkl, 'rb') as file:  
    model = joblib.load(file)

log = open ("ids_log.txt", "w")

print(args.time_diff, args.channel_diff, args.channel)

while (True):
    data = network.receive(time_diff=args.time_diff, channel_diff=args.channel_diff, channel=args.channel, avtp_timestamp=args.avtp)
    print(data)
    if data is None:
        continue
    
    data = data.reshape(1, -1)
    prediction = model.predict(data)

    if prediction[0] == -1:
        print(f"Message Received# Detection: Malicious\n")
        log.write(f"Message Received# Detection: Malicious\n")
    else:
        print(f"Message Received# Detection: Benign\n")
        log.write(f"Message Received# Detection: Benign\n")

    
    