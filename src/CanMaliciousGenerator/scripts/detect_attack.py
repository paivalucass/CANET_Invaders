from CanMaliciousGenerator.detector.data_analyser import DataAnalyser
from CanMaliciousGenerator.detector.ml_detector import Detector
import argparse

argparser = argparse.ArgumentParser(description='CAN Bus Generator of random messages')
argparser.add_argument("dataset", type=str, help='Dataset to use for the CAN Bus')
argparser.add_argument('-t','--type', type=str, default="random", help='Priority of the messages')
argparser.add_argument('-p','--priority', type=bool, default=False, help='Priority of the messages')
args = argparser.parse_args()

data = DataAnalyser(real=[(7,1),(8,1),(13,2),(14,2),(20,1),(21,1),(22,1),(23,1),(65,1),(85,1),(86,1),(91,2),(92,4),(93,1)], dataset=args.dataset)

if args.type == "random":
    if args.priority:
        try:
            dataframe = data.labeler_for_random_messages(priority=True)
        except:
            print("Provided dataset can't be used")
    else:
        try:
            dataframe = data.labeler_for_random_messages()
        except:
            print("Provided dataset can't be used")
            
print(dataframe)


model = Detector()
model.classify(dataframe=dataframe,real=[(7,1),(8,1),(13,2),(14,2),(20,1),(21,1),(22,1),(23,1),(65,1),(85,1),(86,1),(91,2),(92,4),(93,1)])