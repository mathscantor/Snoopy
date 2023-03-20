import socket
from utils.packet import Packet
import struct
import fcntl
import gc
from utils.layer_parsers.link import *
from utils.layer_parsers.network import *
from utils.layer_parsers.transport import *
from utils.layer_parsers.application import *


def get_ip_address_from_nic(nic: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', bytes(nic[:15], "utf-8"))
    )[20:24])


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65565)
        packet = Packet(raw_data=raw_data)
        if packet.application_layer is None:
            continue
        if packet.application_layer.message_type == PFCPMessageType.SESSION_ESTABLISHMENT_REQUEST:
            packet.print_packet()
            print("--------------------------------------------------------------------------------------------")
        del packet
        gc.collect()
    return

if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
