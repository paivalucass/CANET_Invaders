import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.ensemble import IsolationForest
from CanMaliciousGenerator.generator.malicious_generator import MaliciousGenerator
from sklearn import metrics
from sklearn.metrics import ConfusionMatrixDisplay
import matplotlib.pyplot as plt

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
    
    def classify(self, dataframe=None, label='malicious', drop=['malicious'], attack_type="random", generator=MaliciousGenerator(), real=[(0,0)]):
        dataframe = dataframe.sample(frac=1)
        target = dataframe[label]
        print(target)
        target = target.replace([True, False], [-1,1])
        print(target)
        features = dataframe.drop(drop,axis=1)
        self.classifier.fit(features, target)

        id, dlc, data_array, malicious = generator.mix_messages(amount_random=800,amount_real=40,range_id=100,real=real, type=attack_type)
        frame_test = self.create_test_dataframe(id, dlc, data_array, malicious)
        frame_test = frame_test.sample(frac=1)
        test_target = frame_test[label]
        test_target = test_target.replace([True, False], [-1,1])
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