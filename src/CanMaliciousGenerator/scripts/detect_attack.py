from CanMaliciousGenerator.detector.ml_detector import Detector
import argparse

argparser = argparse.ArgumentParser(description='CAN Bus Generator of random messages')
argparser.add_argument("dataset", type=str, help='Dataset path to use for detection')
argparser.add_argument('-t','--type', type=str, default="fuzzing", help='Priority of the messages')
argparser.add_argument('-f','--file', type=str, default="labeled_dataset.txt", help='File to save the labeled dataset')
argparser.add_argument('-m','--model', type=str, default="IsolationForest", help='Model to use for the detection')
args = argparser.parse_args()

model = Detector()
# try:
model.classify(dataset=args.dataset,file_name=args.file,attack_type=args.type)
# except:
#     print("Provided dataset can't be used")
            
