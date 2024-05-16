from CanMaliciousGenerator.CAN_Bus.can_connection import CAN_Bus
from CanMaliciousGenerator.generator.malicious_generator import MaliciousGenerator
import time


bus = CAN_Bus()

while(True):
    real = [(7,1),(8,1),(13,2),(14,2),(20,1),(21,1),(22,1),(23,1),(65,1),(85,1),(86,1),(91,2),(92,4),(93,1)]
    bus.send_random_message(real=real)