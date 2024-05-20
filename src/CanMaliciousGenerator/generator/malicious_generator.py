import numpy as np
import pandas as pd
import cantools
import random
import can


class MaliciousGenerator:
    def __init__(self, real=(0,0)):
        self.real = real
        
    def generate_messages(self, amount, id_amount, real=None, only_one=False, type="random", bus = None):
        if real == None:
            real = self.real
            
        id = []
        data = []
        data_array = []
        dlc = []
        malicious = []
        for x in range(0,amount):
            data = []
            # the lowest the id the higher priority it has 
            if type == "priority":
                id.append(0)
            else:
                id.append(random.randint(0, id_amount))
            dlc.append(random.randint(1,8))

            for y in range(0,int(dlc[x])):
                data.append(random.randint(0, 257))
            for y in range(int(dlc[x]),8):
                data.append(0)
            data_array.append(data)

            if (id[x],dlc[x]) in real:
                malicious.append(False)
            else:
                malicious.append(True)

        if only_one:
            msg = bus.create_message(id=id[0],dlc=dlc[0],data=data_array[0])
            return msg
            
        
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
            ids.append(id)
            dlcs.append(dlc)
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
    
    def mix_messages(self, amount_random=400, amount_real=25, range_id=800, real=[(0,0)], type="random"):
        id_m, dlc_m, data_array_m, malicious_m = self.generate_messages(amount=amount_random, id_amount=range_id, real=real,type=type)
        id = id_m
        dlc = dlc_m
        data_array = data_array_m
        malicious = malicious_m
        for x in range(0,len(real)):
            id_b, dlc_b, data_array_b, malicious_b = self.create_real_messages(id=real[x][0],dlc=real[x][1],amount=amount_real)
            id = id + id_b
            dlc = dlc + dlc_b
            data_array = data_array + data_array_b
            malicious = malicious + malicious_b

        return id, dlc, data_array, malicious