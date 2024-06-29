import argparse
from CAN_Invaders.connection.connector import CAN_Bus
import joblib


argparser = argparse.ArgumentParser(description='CAN Bus Generator of random messages')
argparser.add_argument("model", type=str, help='model path .pkl for ids usage')
argparser.add_argument('-i', '--interface', type=str, default="socketcan", help='Interface to use for the CAN Bus')
argparser.add_argument('-c', '--channel', type=str, default="can0", help='Channel to use for the CAN Bus, use van0 for virtual CAN bus')
argparser.add_argument('-b', '--bitrate', type=str, default="500000", help='Bitrate to use for the CAN Bus')
argparser.add_argument('-f','--features', nargs=3, type=str, default=["True","True","8"], help='Features to use on dataset (id, dlc, bytes) True or False for id and dlc and 0-8 of bytes to use')
args = argparser.parse_args()

bytes = int(args.features[2])
drop = []

for x in range(0,bytes):
    drop.append(f"byte{x+1}")
if args.features[0] == "True":
    drop.append("id")
if args.features[1] == "True":
    drop.append("dlc")
    
# drop_feat = ['id','dlc','byte1','byte2','byte3','byte4','byte5','byte6','byte7','byte8','malicious']
# drop_feat = filter(lambda x: x not in drop, drop_feat)

bus = CAN_Bus(interface=args.interface, channel=args.channel, bitrate=args.bitrate)

with open(args.model, 'rb') as file:  
    model = joblib.load(file)

log = open ("ids_log.txt", "w")

while True:
    features,labels = bus.receive_one()
    features = features.reshape(1, -1)
    # the features selection is currently HARD CODED, TODO: find a way to make it dynamic
    prediction = model.predict(features)
    
    if prediction[0] == -1:
        print(f"Message:{features[0]}# Detection: Malicious\n")
        log.write(f"Message:{features[0]}# Detection: Malicious\n")
    else:
        print(f"Message:{features[0]}# Detection: Benign\n")
        log.write(f"Message:{features[0]}# Detection: Benign\n")
    
