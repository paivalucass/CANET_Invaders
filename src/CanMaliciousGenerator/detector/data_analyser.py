import numpy as np
import pandas as pd

class DataAnalyser:
    def __init__(self, dataset=None):
        self.number_of_runs = 0
        self.dataset = dataset
        
    def create_dataframe(self, data, labels):
        frame_train = pd.DataFrame(data).T
        frame_train.columns = labels
        return frame_train
    
    # (000.005189) can0 00D#4833  <---  messages format look like this
    def split_message(self, message):
        split = message.split()
            
        msg = split[2]
        msg = msg.split("#")
        
        if split[3] == "R":
            malicious = False
        else: 
            malicious = True
        
        payload = msg[1]
        id = msg[0]
        dlc = (len(payload)/2)
        
        return payload, id, dlc, malicious
        
    def labeler_for_random_messages(self, file):
        # splits, label and create a dataframe from a dataset
        file = open(self.dataset,'r')
        labeled = open(file,'w')
        ids = []
        dlcs = []
        byte1_values = []
        byte2_values = []
        byte3_values = []
        byte4_values = []
        byte5_values = []
        byte6_values = []
        byte7_values = []
        byte8_values = []
        malicious = []
        is_malicious = False
        for message in file:
            payload, id, dlc, malicious = self.split_message(message)
            bytes_array = [int(payload[i:i+2], 16) for i in range(0, len(payload), 2)]
            bytes_array += [0] * (8 - len(bytes_array))

            ids.append(int(id,16))
            dlcs.append(int(dlc))               
            labeled.write(f"{int(id,16)}#{int(dlc)}#{payload}#{is_malicious}\n")
            byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8 = bytes_array
            byte1_values.append(byte1)
            byte2_values.append(byte2)
            byte3_values.append(byte3)
            byte4_values.append(byte4)
            byte5_values.append(byte5)
            byte6_values.append(byte6)
            byte7_values.append(byte7)
            byte8_values.append(byte8)
        
        labels = ['id','dlc','byte1','byte2','byte3','byte4','byte5','byte6','byte7','byte8','malicious']
        data = [ids,dlcs,byte1_values,byte2_values,byte3_values,byte4_values,byte5_values,byte6_values,byte7_values,byte8_values,malicious]
        
        file.close()
        labeled.close()
        
        return self.create_dataframe(data,labels)
    
    