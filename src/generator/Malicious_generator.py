import numpy as np
import pandas as pd
import cantools
import random
import can
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.ensemble import IsolationForest

class Malicious_generator:
    def __init__(self, real=(0,0)):
        self.real = real
        
    def create_random_messages(self, amount, id_amount, real=(0,0)):
        id = []
        data = []
        data_array = []
        dlc = []
        malicious = []
        for x in range(0,amount):
            data = []
            id.append(float(random.randint(0, id_amount)))
            dlc.append(float(random.randint(1,8)))

            for y in range(0,int(dlc[x])):
                data.append(random.randint(0, 257))
            for y in range(int(dlc[x]),8):
                data.append(0)
            data_array.append(data)

            if (int(id[x]),int(dlc[x])) in real:
                malicious.append(False)
            else:
                malicious.append(True)

        
        return id, dlc, data_array, malicious
    
    def create_real_messages(self, id, dlc, amount):
        ids = []
        dlcs = []
        data = []
        data_array = []
        malicious = []
        flag = 0
        for x in range(0,amount):
            data = []
            ids.append(float(id))
            dlcs.append(float(dlc))
            if flag == 0:
                for y in range(0,dlc):
                    data.append(256)
            elif flag == 1:
                for y in range(0,dlc):
                    data.append(0)
            else:
                for y in range(0,dlc):
                    data.append(random.randint(0, 257))
            for y in range(dlc,8):
                data.append(0)
            data_array.append(data)
            malicious.append(False)
            flag += 1

        return ids, dlcs, data_array, malicious
    
    def mix_messages(self, amount_random=400, amount_real=25, range_id=800, real=[(0,0)]):
        id_m, dlc_m, data_array_m, malicious_m = self.create_random_messages(amount_random, range_id, real)
        id = id_m
        dlc = dlc_m
        data_array = data_array_m
        malicious = malicious_m
        for x in range(0,len(real)):
            id_b, dlc_b, data_array_b, malicious_b = self.create_real_messages(real[x][0],real[x][1],amount_real)
            id = id + id_b
            dlc = dlc + dlc_b
            data_array = data_array + data_array_b
            malicious = malicious + malicious_b

        return id, dlc, data_array, malicious