import numpy as np
import random
import can
from CAN.detection.dataset import DatasetCreator


class Generator:
    def __init__(self):
        pass
    
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
        
        return id_false, dlc_false, data, -1
    
