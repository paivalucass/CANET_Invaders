import numpy as np
import pandas as pd

class DataAnalyser:
    def __init__(self, real):
        self.real = real
        self.number_of_runs = 0
        
    def create_dataframe(self, data, labels):
        frame_train = pd.DataFrame(data).T
        frame_train.columns = labels
        return frame_train
    
    # (000.005189) can0 00D#4833  <---  messages format look like this
    def split_message(self, message):
        split = message.split()
            
        msg = split[2]
        msg = msg.split("#")
            
        payload = msg[1]
        id = msg[0]
        dlc = (len(payload)/2)
        
        return payload, id, dlc
        
    def labeler_for_random_messages(self, dataset, priority=False):
        # splits, label and create a dataframe from a dataset
        file = open(dataset,'r')
        labeled = open('labeled.txt','w')
        ids = []
        dlcs = []
        payloads = []
        malicious = []
        is_malicious = False
        for message in file:
            payload, id, dlc = self.split_message(message)
            
            if not priority:
                if (int(id,16),int(dlc)) in self.real:
                    malicious.append(False)
                    is_malicious = False
                else: 
                    malicious.append(True)
                    is_malicious = True
            else:
                if id == "000":
                    malicious.append(True)
                    is_malicious = True
                else: 
                    malicious.append(False)
                    is_malicious = False
            
            ids.append(int(id,16))
            dlcs.append(int(dlc))
            payloads.append(int(payload,16))
            labeled.write(f"{int(id,16)}#{int(dlc)}#{int(payload,16)}#{is_malicious}\n")
            # Attention! payload threated as one big number, might be a TODO: to separete by bytes
            
        labels = ['id','dlc','paylaod','malicious']
        data = [ids,dlcs,payloads,malicious]
        
        file.close()
        labeled.close()
        
        return self.create_dataframe(data,labels)
    
    