import argparse
from CAN_Invaders.connection.connector import CAN_Bus
import pandas as pd
import pickle


argparser = argparse.ArgumentParser(description='CAN Bus Generator of random messages')
argparser.add_argument("model", type=str, help='model path .pkl for ids usage')
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
    
drop_feat = ['id','dlc','byte1','byte2','byte3','byte4','byte5','byte6','byte7','byte8','malicious']
drop_feat = drop.filter(lambda x: x not in drop, drop_feat)

bus = CAN_Bus()
# TODO: model loading need to be REWORKED ASAP in order to make the ids work again
with open(args.dataset, 'rb') as file:  
    model = pickle.load(file)

log = open ("ids_log.txt", "w")

while True:
    try:
        features,labels = bus.receive_one()
        # the features selection is currently HARD CODED, TODO: find a way to features selection to work 
        prediction = model.predict(features)
        log.write(f"{features}#{prediction[0]}\n")
    except:
        log.close()
        print("IDS System stopped")