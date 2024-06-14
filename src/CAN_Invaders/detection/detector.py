import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import classification_report
from sklearn import metrics
from sklearn.svm import OneClassSVM
import matplotlib.pyplot as plt
from CAN_Invaders.detection.dataset import DatasetCreator

class Detector:
    def __init__(self, model="IsolationForest"):
        self.model = model 
        
    def create_dataframe(self, data, labels):
        frame_train = pd.DataFrame(data).T
        frame_train.columns = labels
        return frame_train
    
    def classify(self, dataset_train, dataset_test=None, verbose=True, size_train = 700000, file_name="labeled_dataset.txt", label='malicious', drop=['malicious']):
        # TODO: refactor how training and testing dataset are separeted
        # TODO: User doesnt need to know about the dataset size, refactor this ASAP
        # TODO: less arguments on fuction call
        
        data = DatasetCreator(dataset=dataset_train)
        size_dataset = data.count()
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
                data_test = DatasetCreator(dataset=dataset_test)
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
                data_test = DatasetCreator(dataset=dataset_test)
                test_frame = data_test.label_messages(file_name="test_dataset.txt")
                
            test_target = test_frame[label]
            test_frame = test_frame.drop(drop,axis=1)
            prediction = classifier.predict(test_frame)
        else: 
            print("Model still not implemented")
            return None
        
        if verbose:
            
            if self.model == "IsolationForest" or self.model == "OneClassSVM":
                print("Classification Report for " + self.model)
                print(classification_report(target, prediction))
            else:
                print("Classification Report for " + self.model)
                print(classification_report(test_target, prediction))

            if self.model == "IsolationForest" or self.model == "OneClassSVM":
                confusion_matrix = metrics.confusion_matrix(target, prediction)
            else:
                confusion_matrix = metrics.confusion_matrix(test_target, prediction)
            cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix = confusion_matrix, display_labels=["Malicious","No Malicious"])
            cm_display.plot()
            plt.show()
        
        return classifier