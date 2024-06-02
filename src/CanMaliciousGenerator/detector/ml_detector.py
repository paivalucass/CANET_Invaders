import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.ensemble import IsolationForest
from CanMaliciousGenerator.generator.malicious_generator import MaliciousGenerator
from sklearn import metrics
from sklearn.metrics import ConfusionMatrixDisplay
import matplotlib.pyplot as plt
from CanMaliciousGenerator.detector.data_analyser import DataAnalyser

class Detector:
    def __init__(self, classifier=IsolationForest()):
        self.classifier = classifier
        
    def create_dataframe(self, data, labels):
        frame_train = pd.DataFrame(data).T
        frame_train.columns = labels
        return frame_train
    
    def create_test_dataframe(self, id, dlc, data_array, malicious):
        byte1_values = []
        byte2_values = []
        byte3_values = []
        byte4_values = []
        byte5_values = []
        byte6_values = []
        byte7_values = []
        byte8_values = []
        
        for i in range(0, len(data_array)):
            byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8 = data_array[i]
            byte1_values.append(byte1)
            byte2_values.append(byte2)
            byte3_values.append(byte3)
            byte4_values.append(byte4)
            byte5_values.append(byte5)
            byte6_values.append(byte6)
            byte7_values.append(byte7)
            byte8_values.append(byte8)
            
        labels = ['id','dlc','byte1','byte2','byte3','byte4','byte5','byte6','byte7','byte8','malicious']
        data = [id,dlc,byte1_values,byte2_values,byte3_values,byte4_values,byte5_values,byte6_values,byte7_values,byte8_values,malicious]
        
        frame_test = self.create_dataframe(data=data,labels=labels)
        #shuffle dataframe
        frame_test = frame_test.sample(frac = 1)
        
        return frame_test
    
    def classify(self, dataset=None, file_name="labeled_dataset.txt", label='malicious', drop=['malicious', 'id', 'dlc'], attack_type="fuzzing", generator=MaliciousGenerator()):
        
        data = DataAnalyser(dataset=dataset)
        dataframe = data.label_messages(file_name=file_name)
        
        # original dataset 
        dataframe = dataframe.sample(frac=1)
        target = dataframe[label]
        print(dataframe)
        features = dataframe.drop(drop,axis=1)
        self.classifier.fit(features, target)
        
        
        # creating a test dataset
        id, dlc, data_array, malicious = generator.mix_messages(data=data, amount_attack=400, amount_real=400, range_id=200, type=attack_type)
        frame_test = self.create_test_dataframe(id, dlc, data_array, malicious)
        frame_test = frame_test.sample(frac=1)
        test_target = frame_test[label]
        frame_test = frame_test.drop(drop,axis=1)
        

        predictions = self.classifier.predict(frame_test)
        accuracy = accuracy_score(test_target, predictions)
        print(accuracy)
        
        print(predictions)
        
        confusion_matrix = metrics.confusion_matrix(test_target, predictions)
        cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix = confusion_matrix, display_labels=["Malicious","No Malicious"])

        cm_display.plot()
        plt.show()
        
        return accuracy
