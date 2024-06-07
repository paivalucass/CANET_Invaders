from CanMaliciousGenerator.detector.ml_detector import Detector
import argparse
from CanMaliciousGenerator.CAN_Bus.can_connection import CAN_Bus
import pandas as pd
import pickle


argparser = argparse.ArgumentParser(description='CAN Bus Generator of random messages')
argparser.add_argument("dataset", type=str, help='Dataset path to use for detection')
argparser.add_argument()
args = argparser.parse_args()
#TODO: make drop system 
#TODO: test!!!

bus = CAN_Bus()

with open(args.dataset, 'rb') as file:  
    model = pickle.load(file)

while True:
    dataframe = bus.receive_one()
    print(dataframe)
    label = dataframe['malicious']
    features = dataframe.drop(drop,axis=1)
    prediction = model.predict(features)
        
    file.write(f"{dataframe}{prediction[0]}\n")
    