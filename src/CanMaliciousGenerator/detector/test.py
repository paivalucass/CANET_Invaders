from data_analyser import DataAnalyser
from detector import Detector


data = DataAnalyser(real=[(7,1),(8,1),(13,2),(14,2),(20,1),(21,1),(22,1),(23,1),(65,1),(85,1),(86,1),(91,2),(92,4),(93,1)])
dataframe = data.labeler_for_random_messages(dataset="/home/lucas/WIP_PET/Malicious_CAN_Bus_detector/dataset/fuzzing copy.txt")
print(dataframe)


model = Detector()
model.classify(dataframe=dataframe,real=[(7,1),(8,1),(13,2),(14,2),(20,1),(21,1),(22,1),(23,1),(65,1),(85,1),(86,1),(91,2),(92,4),(93,1)])