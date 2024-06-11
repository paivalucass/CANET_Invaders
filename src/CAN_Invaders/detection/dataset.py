import pandas as pd

class DatasetCreator:
    def __init__(self, dataset=None):
        
        self.dataset = dataset
        
    def create_dataframe(self, data, labels):
        frame_train = pd.DataFrame(data).T
        frame_train.columns = labels
        return frame_train
    
    # def find_id(self):
    #     payload = 0
    #     id = 0
    #     dlc = 0
    #     malicious = False
    #     file = open(self.dataset,'r')
    #     for message in file:
    #         payload, id, dlc, malicious  = self.split_message(message)
    #         if malicious == -1:
    #             file.close()
    #             return id, dlc
            
    # def collect_real(self, amount):
    #     count = 0
    #     ids = []
    #     dlcs = []
    #     malicious = []
    #     payloads = []
    #     file = open(self.dataset, 'r')
    #     for message in file:
    #         payload, id, dlc, is_malicious = self.split_message(message)
    #         bytes_array = [int(payload[i:i+2], 16) for i in range(0, len(payload), 2)]
    #         bytes_array += [0] * (8 - len(bytes_array))
    #         if is_malicious == 1:
    #             id = int(id,16)
    #             dlc = int(dlc)
    #             ids.append(id)
    #             dlcs.append(dlc)
    #             malicious.append(is_malicious)
    #             payloads.append(bytes_array)
    #             count += 1
    #         if count == amount:
    #             break
    #     file.close()
    #     return ids, dlcs, malicious, payloads
            
                    
    # (000.005189) can0 00D#4833  <---  messages format look like this (default log format)
    def split_message(self, message):
        split = message.split()
        
        aux = split[0].split(".")
        time = aux[1].replace(')','')
        
        msg = split[2]
        msg = msg.split("#")
        
        if split[3] == "R":
            malicious = 1
        else: 
            malicious = -1
        
        payload = msg[1]
        id = msg[0]
        dlc = (len(payload)/2)
        
        return payload, id, dlc, malicious, time
        
    def label_messages(self, file_name, end=700000, start=0):
        # splits, label and create a dataframe from a dataset
        count = 0
        file = open(self.dataset,'r')
        labeled = open(file_name,'w')
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
        times = []
        is_malicious = False
        for message in file:
            if count < start:
                count += 1
                continue
            payload, id, dlc, is_malicious, time = self.split_message(message)
            bytes_array = [int(payload[i:i+2], 16) for i in range(0, len(payload), 2)]
            bytes_array += [0] * (8 - len(bytes_array))
            byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8 = bytes_array
            byte1_values.append(byte1)
            byte2_values.append(byte2)
            byte3_values.append(byte3)
            byte4_values.append(byte4)
            byte5_values.append(byte5)
            byte6_values.append(byte6)
            byte7_values.append(byte7)
            byte8_values.append(byte8)  
            malicious.append(is_malicious)
            labeled.write(f"{int(id,16)}#{int(dlc)}#{payload}#{is_malicious}\n")
            ids.append(int(id,16))
            dlcs.append(int(dlc))   
            count += 1
            if count == end:
                break

        labels = ['id','dlc','byte1','byte2','byte3','byte4','byte5','byte6','byte7','byte8','malicious']
        data = [ids,dlcs,byte1_values,byte2_values,byte3_values,byte4_values,byte5_values,byte6_values,byte7_values,byte8_values,malicious]              
                                    
        file.close()
        labeled.close()
        
        return self.create_dataframe(data,labels)
    
    