import numpy as np
import cantools
import random
import can
from CanMaliciousGenerator.detector.data_analyser import DataAnalyser


class MaliciousGenerator:
    def __init__(self, real=(0,0)):
        self.real = real
        
    def generate_messages(self, amount, id_amount, only_one=False, type="fuzzing", bus = None):
            
        id = []
        data = []
        data_array = []
        dlc = []
        malicious = []
        
        for x in range(0,amount):
            data = []
            # the lowest the id the higher priority it has 
            if type == "doS":
                id.append(0)
            elif type == "target":
                id.append(id_amount)
            else:
                id.append(random.randint(0, id_amount))
            dlc.append(random.randint(1,8))

            for y in range(0,int(dlc[x])):
                data.append(random.randint(0, 255))
            for y in range(int(dlc[x]),8):
                data.append(0)
            data_array.append(data)
        
            malicious.append(-1)

        if only_one:
            msg = bus.create_message(id=id[0],dlc=dlc[0],data=data_array[0])
            return msg
        
        return id, dlc, data_array, malicious
    
    def generate_specific_message(self, id, dlc, binary=0, bus= None, type="impersonation", message=False):
        id_false = id
        dlc_false = dlc
        data = []
        if type == "falsifying":
            dlc_false = random.randint(1,8)
            
        if binary == 1:
            for y in range(0,dlc_false):
                data.append(random.randint(0,1))
            for y in range(dlc_false,8):
                data.append(0)
        else:
            for y in range(0,dlc_false):
                data.append(random.randint(0, 255))
            for y in range(dlc_false,8):
                data.append(0)
                
        if message:
            msg = bus.create_message(id=id_false,dlc=dlc_false,data=data)
            return msg
        
        return id_false, dlc_false, data, True 
    
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
                    data.append(random.randint(0, 255))
            for y in range(dlc,8):
                data.append(0)
            data_array.append(data)
            malicious.append(False)
            flag += 1

        return ids, dlcs, data_array, malicious
    
    def mix_messages(self, data, amount_attack=400, amount_real=400, range_id=200, type="fuzzing"):
        id = []
        dlc = []
        data_array = []
        malicious = []
        # fuzzing generator for test dataset
        if type == "fuzzing" or "doS":
            id_m, dlc_m, data_array_m, malicious_m = self.generate_messages(amount=amount_attack, id_amount=range_id, type=type)
            id = id_m
            dlc = dlc_m
            data_array = data_array_m
            malicious = malicious_m
            
        # impersonation or falsifying generator for test dataset
        else:
            # find the id and dlc used in the actual attack
            id_target, dlc_target = data.find_id()
            for x in range(0, amount_attack):
                
                if type == "impersonation":
                    id_m, dlc_m, data_array_m, malicious_m = self.generate_specific_message(id=id_target, dlc=dlc_target, binary=0, type=type)
                    
                else:
                    id_m, dlc_m, data_array_m, malicious_m = self.generate_specific_message(id=id_target, dlc=1, binary=0, type=type)
                    
                id = id + id_m
                dlc = dlc + dlc_m
                data_array = data_array + data_array_m
                malicious = malicious + malicious_m
                
        # collect real messages for test dataset from the actual dataset
        id_b, dlc_b, malicious_b, data_array_b = data.collect_real(amount=amount_real)
        id = id + id_b
        dlc = dlc + dlc_b
        data_array = data_array + data_array_b
        malicious = malicious + malicious_b
        print(id)
        print(dlc)
        print(data_array)
        print(malicious)
        return id, dlc, data_array, malicious