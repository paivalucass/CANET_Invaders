import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.ensemble import IsolationForest, RandomForestClassifier, HistGradientBoostingClassifier
from CanMaliciousGenerator.generator.malicious_generator import MaliciousGenerator
from sklearn.metrics import classification_report
from sklearn import metrics
from sklearn.metrics import ConfusionMatrixDisplay
from sklearn.svm import OneClassSVM
import matplotlib.pyplot as plt
from CanMaliciousGenerator.detector.data_analyser import DataAnalyser

class Detector:
    def __init__(self, model="IsolationForest"):
        self.model = model 
        
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
        payloads = []
        
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
    
    def classify(self, dataset_train, size_dataset=700000, dataset_test=None, verbose=True, size_train = 700000, file_name="labeled_dataset.txt", label='malicious', drop=['malicious']):
        # BEST FEATURES MODEL SO FAR: ID , DLC AND 3 BYTES OF PAYLOAD
        # size of test dataset is size_total-size_train
        #TODO: separete train and test dataset
        #'byte1','byte2','byte3','byte4','byte5','byte6','byte7','byte8'
        
        data = DataAnalyser(dataset=dataset_train)
        dataframe = data.label_messages(file_name=file_name, end=size_train)
        target = dataframe[label]
        
        if self.model == "IsolationForest":
            #CONTAMINATION RATE CHANGES ACCORDING TO THE AMOUNT OF MALICIOUS MESSAGES 
            aux = len([v for v in list(dataframe["malicious"]) if v==-1]) 
            contamination = aux/len(dataframe["malicious"])
            classifier=IsolationForest(contamination=contamination, random_state=42)
            features = dataframe.drop(drop,axis=1)
            classifier.fit(features)
            prediction = classifier.predict(features)
            
        elif self.model == "RandomForest":
            classifier=RandomForestClassifier(random_state=42)
            features = dataframe.drop(drop,axis=1)
            classifier.fit(features, target)
            
            if not dataset_test:
                test_frame = data.label_messages(file_name=file_name, end=size_dataset, start=size_train)
            else:
                data_test = DataAnalyser(dataset=dataset_test)
                test_frame = data_test.label_messages(file_name="test_dataset.txt")
                
            test_target = test_frame[label]
            test_frame = test_frame.drop(drop,axis=1)
            prediction = classifier.predict(test_frame)
            
        elif self.model == "OneClassSVM":
            classifier=OneClassSVM(gamma="auto")
            features = dataframe.drop(drop,axis=1)
            classifier.fit(features)
            prediction = classifier.predict(features)
            
        elif self.model == "Boosting":
            classifier=HistGradientBoostingClassifier(random_state=42)
            features = dataframe.drop(drop,axis=1)
            classifier.fit(features, target)
            
            if not dataset_test:
                test_frame = data.label_messages(file_name=file_name, end=size_dataset, start=size_train)
            else:
                data_test = DataAnalyser(dataset=dataset_test)
                test_frame = data_test.label_messages(file_name="test_dataset.txt")
                
            test_target = test_frame[label]
            test_frame = test_frame.drop(drop,axis=1)
            prediction = classifier.predict(test_frame)
        else: 
            print("Model still not implemented")
            return None
        
        if self.model == "IsolationForest" or self.model == "OneClassSVM":
            print("Classification Report for" + self.model)
            print(classification_report(target, prediction))
        else:
            print("Classification Report for" + self.model)
            print(classification_report(test_target, prediction))
        
        if verbose:
            if self.model == "IsolationForest" or self.model == "OneClassSVM":
                confusion_matrix = metrics.confusion_matrix(target, prediction)
            else:
                confusion_matrix = metrics.confusion_matrix(test_target, prediction)
            cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix = confusion_matrix, display_labels=["Malicious","No Malicious"])
            cm_display.plot()
            plt.show()
        
        return classifier