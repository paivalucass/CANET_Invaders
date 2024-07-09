from Ethernet.detection.ethernet_connector import Ethernet


e = Ethernet(interface="eth10")


while True:
    e.listen_epoch()
