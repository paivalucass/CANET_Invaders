from CAN.generation.generator import Generator
import can
import pandas as pd
import numpy as np


class CAN_Bus:
    def __init__(self, interface="socketcan", channel="can0", bitrate="500000"):
        self.bus = can.Bus(interface=interface,channel=channel, bitrate=bitrate)
        self.generator = Generator()
    
    def create_dataframe(self, data, labels):
        frame = pd.DataFrame(data).T
        frame.columns = labels
        return frame
    
    def send_one(self, msg):
            # this uses the default configuration (for example from the config file)
            # see https://python-can.readthedocs.io/en/stable/configuration.html
            # TODO: implement for different can bus types as shown below
            # Using specific buses works similar:
            # bus = can.Bus(interface='socketcan', channel='vcan0', bitrate=250000)
            # bus = can.Bus(interface='pcan', channel='PCAN_USBBUS1', bitrate=250000)
            # bus = can.Bus(interface='ixxat', channel=0, bitrate=250000)
            # bus = can.Bus(interface='vector', app_name='CANalyzer', channel=0, bitrate=250000)
            # ...
            try:
                self.bus.send(msg)
                print(f"Message sent on {self.bus.channel_info}")
            except can.CanError:
                print("ERROR! Message NOT sent")
                
    ## The malicious distinction is made by the RX/TX bit so set the is_rx to False 
    def create_message(self, id, dlc, data=[0,0,0,0,0,0,0,0], extended=False, is_rx=False):
        try:
            return can.Message(arbitration_id=id, data=data, dlc=dlc, is_extended_id=extended, is_rx=is_rx)
        except can.CanError: 
            print("ERROR! Message NOT created")
    
    def receive_one(self):
        try: 
            msg = self.bus.recv()
            print(f"Message received on {self.bus.channel_info}")
        except can.CanError:
            print("ERROR! Message NOT received")
            
        id = msg.arbitration_id
        data = msg.data.hex()
        bytes_array = [int(data[i:i+2], 16) for i in range(0, len(data), 2)]
        bytes_array += [0] * (8 - len(bytes_array))
        byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8 = bytes_array
        dlc = msg.dlc
        
        if msg.is_rx:
            malicious = "R"
            
        else: 
            malicious = "T"
            
        labels = ['id','dlc','byte1','byte2','byte3','byte4','byte5','byte6','byte7','byte8','malicious']
        data = [id, dlc, byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8]      
        
        labels = np.array(labels)
        data = np.array(data)

        return data, labels
    
    def send_message(self, bus, type="fuzzing", id=0, dlc=1, binary=0):
        if type == "fuzzing" or type == "doS":
            self.send_random_message(bus=bus, type=type)
        elif type == "impersonation" or type == "falsifying":
            self.send_specific_message(bus=bus, id=id, dlc=dlc, type=type, binary=binary)
        else:
            ("Attack type not implemented")
            
    def send(self, id, dlc, data=[0,0,0,0,0,0,0,0], extended=False, is_rx=False):
        msg = self.create_message(id=id, dlc=dlc, data=data, extended=extended, is_rx=is_rx)
        self.send_one(msg=msg)
        
    def send_random_message(self, bus, type="fuzzing"):
        msg = self.generator.generate_messages(amount=1, id_amount=200, only_one=True, bus=bus, type=type)
        self.send_one(msg=msg)
        
    def send_specific_message(self, bus, id=0, dlc=1, type="impersonation", binary=0):
        msg = self.generator.generate_specific_message(id=id, dlc=dlc, bus=bus, type=type, binary=binary, message=True)
        self.send_one(msg=msg)