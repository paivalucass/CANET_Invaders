import numpy as np
import pandas as pd
import cantools
import random
import can
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.ensemble import IsolationForest

class Detector:
    def __init__(self):
        pass
    def create_dataframe(data,labels):
        frame_train = pd.DataFrame(data).T
        frame_train.columns = labels
        return frame_train