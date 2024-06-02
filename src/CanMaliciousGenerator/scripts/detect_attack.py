from CanMaliciousGenerator.detector.data_analyser import DataAnalyser
from CanMaliciousGenerator.detector.ml_detector import Detector
import argparse

argparser = argparse.ArgumentParser(description='CAN Bus Generator of random messages')
argparser.add_argument("dataset", type=str, help='Dataset to use for the CAN Bus')
argparser.add_argument('-t','--type', type=str, default="random", help='Priority of the messages')
argparser.add_argument('-f','--file', type=str, default="labeled_dataset.txt", help='File to save the labeled dataset')

args = argparser.parse_args()

data = DataAnalyser(dataset=args.dataset)

try:
    dataframe = data.labeler_for_random_messages(file_name=args.file)
except:
    print("Provided dataset can't be used")
            
print(dataframe)


model = Detector()
model.classify(dataframe=dataframe,real=[(7,1),(8,1),(13,2),(14,2),(20,1),(21,1),(22,1),(23,1),(65,1),(85,1),(86,1),(91,2),(92,4),(93,1)])