from CanMaliciousGenerator.CAN_Bus.can_connection import CAN_Bus
from CanMaliciousGenerator.generator.malicious_generator import MaliciousGenerator
import argparse



argparser = argparse.ArgumentParser(description='CAN Bus Generator of random messages')
argparser.add_argument('-i', '--interface', type=str, default="socketcan", help='Interface to use for the CAN Bus')
argparser.add_argument('-c', '--channel', type=str, default="can0", help='Channel to use for the CAN Bus')
argparser.add_argument('-b', '--bitrate', type=str, default="500000", help='Bitrate to use for the CAN Bus')
argparser.add_argument('-t', '--type', type=str, default="random", help='Type of the messages to be generated')
args = argparser.parse_args()

bus = CAN_Bus(real=[(7,1),(8,1),(13,2),(14,2),(20,1),(21,1),(22,1),(23,1),(65,1),(85,1),(86,1),(91,2),(92,4),(93,1)], 
              interface=args.interface,
              channel=args.channel, 
              bitrate=args.bitrate)

while(True):
    bus.send_random_message(bus, type=args.type)
