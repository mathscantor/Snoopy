import socket
from utils.packet import Packet
import struct
import fcntl
import gc


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
        packet.print_packet()
        del packet
        print("--------------------------------------------------------------------------------------------")
        gc.collect()
    return

if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
