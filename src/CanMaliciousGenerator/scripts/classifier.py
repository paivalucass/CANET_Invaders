from CanMaliciousGenerator.detector.ml_detector import Detector
import argparse
from CanMaliciousGenerator.CAN_Bus.can_connection import CAN_Bus
import pandas as pd
import pickle

argparser = argparse.ArgumentParser(description='CAN Bus Generator of random messages')
argparser.add_argument("dataset", type=str, help='Dataset path to use for detection')
argparser.add_argument('-t','--type', type=str, default="fuzzing", help='Priority of the messages')
argparser.add_argument('-f','--file', nargs=2, type=str, default=["labeled_dataset.txt", "ids_model.pkl"], help='File to save the labeled dataset / File to save the model')
argparser.add_argument('-m','--model', type=str, default="IsolationForest", help='Model to use for the detection')
argparser.add_argument('-s','--size', nargs=2, type=int, default=[700000,700000], help='Size of the dataset / Size of the training dataset ! Attention ! if the size of train < size dataset and you havent provided a proper test dataset, the remaining data will be used for testing.')
args = argparser.parse_args()

model = Detector(model=args.model)
# try:
classifier = model.classify(dataset_train=args.dataset,file_name=args.file[0], size_dataset=args.size[0], size_train=args.size[1])

with open(args.file[1], 'wb') as model:
    pickle.dump(classifier, model)
    
model.close()
    