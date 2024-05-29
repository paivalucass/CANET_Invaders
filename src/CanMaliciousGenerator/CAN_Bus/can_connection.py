from CanMaliciousGenerator.generator.malicious_generator import MaliciousGenerator
import cantools
import can


class CAN_Bus:
    def __init__(self, real, interface="socketcan", channel="can0", bitrate="500000"):
        self.bus = can.Bus(interface=interface,channel=channel, bitrate=bitrate)
        self.generator = MaliciousGenerator(real)
    
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
                
    def create_message(self, id, dlc, data=[0,0,0,0,0,0,0,0], extended=False):
        return can.Message(arbitration_id=id, data=data, dlc=dlc, is_extended_id=extended)
    
    def receive_one(self):
            try: 
                msg = self.bus.recv()
                print(f"Message received on {self.bus.channel_info}")
            except can.CanError:
                print("ERROR! Message NOT received")
                
    # def create_listener(self):
    #     with can.Bus(receive_own_messages=True) as bus: 
    #         printer = can.Printer()
    #         can.Notifier(bus, [printer])
    
    def send_message(self, bus, type="fuzzing", id="0", dlc="0"):
        if type == "fuzzing" or type == "doS":
            self.send_random_message(bus=bus, type=type)
        elif type == "impersonation" or type == "falsifying":
            self.send_specific_message(bus=bus, id=id, dlc=dlc, type=type)
        else:
            pass
        
    def send_random_message(self, bus, type="fuzzing"):
        msg = self.generator.generate_messages(amount=1, id_amount=200, only_one=True, bus=bus, type=type)
        self.send_one(msg=msg)
        
    def send_specific_message(self, bus, id="0", dlc="1", type="impersonation"):
        msg = self.generator.generate_specific_message(id=id, dlc=dlc, bus=bus, type=type)
        self.send_one(msg=msg)