from CanMaliciousGenerator.CAN_Bus.can_connection import CAN_Bus
from CanMaliciousGenerator.generator.malicious_generator import MaliciousGenerator
import argparse
import time

argparser = argparse.ArgumentParser(description='CAN Bus Generator of random messages')
argparser.add_argument('-i', '--interface', type=str, default="socketcan", help='Interface to use for the CAN Bus')
argparser.add_argument('-c', '--channel', type=str, default="can0", help='Channel to use for the CAN Bus')
argparser.add_argument('-b', '--bitrate', type=str, default="500000", help='Bitrate to use for the CAN Bus')
argparser.add_argument('-t', '--type', type=str, default="fuzzing", help='Type of the messages to be generated')
argparser.add_argument('-s', '--sleep', type=float, default=0.000001, help='Type attack frequency')
args = argparser.parse_args()

bus = CAN_Bus(interface=args.interface,
              channel=args.channel, 
              bitrate=args.bitrate)

while(True):
    time.sleep(args.sleep)
    bus.send_message(bus, type=args.type)
