import argparse
from CanMaliciousGenerator.CAN_Bus.can_connection import CAN_Bus
import pandas as pd
import pickle


argparser = argparse.ArgumentParser(description='CAN Bus Generator of random messages')
argparser.add_argument("dataset", type=str, help='Dataset path to use for detection')
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

with open(args.dataset, 'rb') as file:  
    model = pickle.load(file)

while True:
    dataframe = bus.receive_one()
    print(dataframe)
    label = dataframe['malicious']
    features = dataframe.drop(list(drop_feat),axis=1)
    prediction = model.predict(features)
        
    file.write(f"{dataframe}{prediction[0]}\n")

file.close()