from utils.layer_parsers.application.application import ApplicationType
from utils.layer_parsers.transport.transport import TransportLayer
import struct


class TCP(TransportLayer):

    def __init__(self, transport_type, transport_data):
        TransportLayer.__init__(self, transport_type, transport_data)
        self._sequence = None
        self._acknowledgement = None
        self._header_length = None
        self._flags = None
        self._flag_urg = None
        self._flag_ack = None
        self._flag_psh = None
        self._flag_rst = None
        self._flag_syn = None
        self._flag_fin = None
        self._parse_data()

    def _parse_data(self):
        self._src_port, \
            self._dest_port, self._sequence, \
            self._acknowledgement, self._flags = struct.unpack('! H H L L H',
                                                               self._transport_data[:14])
        self._header_length = (self._flags >> 12) * 4
        self._flag_urg = (self._flags & 32) >> 5
        self._flag_ack = (self._flags & 16) >> 4
        self._flag_psh = (self._flags & 8) >> 3
        self._flag_rst = (self._flags & 4) >> 2
        self._flag_syn = (self._flags & 2) >> 1
        self._flag_fin = self._flags & 1
        self._application_data = self._transport_data[self._header_length:]

        if len(self._application_data) == 0:
            return

        if self.is_padding(self._application_data):
            return

        self._application_type = ApplicationType(self._src_port)
        if self._application_type != ApplicationType.UNKNOWN:
            return

        self._application_type = ApplicationType(self._dest_port)
        return

    def print_data(self):
        print("TCP Data:")
        print("\t+Source Port: {}\n"
              "\t+Destination Port: {}\n"
              "\t+Sequence: {}\n"
              "\t+Acknowledgement: {}\n"
              "\t+Offset: {}\n"
              "\t+FLAGS:\n"
              "\t\t+URG: {}\n"
              "\t\t+ACK: {}\n"
              "\t\t+PSH: {}\n"
              "\t\t+RST: {}\n"
              "\t\t+SYN: {}\n"
              "\t\t+FIN: {}\n"
              "\t+Application Type: {}".format(self._src_port,
                                               self._dest_port,
                                               self._sequence,
                                               self._acknowledgement,
                                               self._header_length,
                                               self._flag_urg,
                                               self._flag_ack,
                                               self._flag_psh,
                                               self._flag_rst,
                                               self._flag_syn,
                                               self._flag_fin,
                                               self._application_type))
        return

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def acknowledgement(self) -> int:
        return self._acknowledgement

    @property
    def header_length(self) -> int:
        return self._header_length

    @property
    def flags(self) -> int:
        return self._flags

    @property
    def flag_urg(self) -> int:
        return self._flag_urg

    @property
    def flag_ack(self) -> int:
        return self._flag_ack

    @property
    def flag_psh(self) -> int:
        return self._flag_psh

    @property
    def flag_rst(self) -> int:
        return self._flag_rst

    @property
    def flag_syn(self) -> int:
        return self._flag_syn

    @property
    def flag_fin(self) -> int:
        return self._flag_fin

# TODO: Handle packet reassembly using chatGPT's method.
# import socket
# import struct
#
# # Define a function to reassemble TCP packets
# def tcp_reassemble():
#     # Create a raw socket to capture all IP packets
#     sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
#     sock.bind(("127.0.0.1", 0))
#     sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
#     sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
#
#     # Initialize an empty dictionary to store the TCP segments
#     segments = {}
#
#     # Loop forever to capture packets and reassemble TCP data
#     while True:
#         # Receive a packet from the socket
#         packet, _ = sock.recvfrom(65535)
#
#         # Extract the IP header from the packet
#         ip_header = packet[0:20]
#         iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
#
#         # Extract the protocol number from the IP header (should be 6 for TCP)
#         protocol = iph[6]
#
#         if protocol == 6:
#             # Extract the TCP header from the packet
#             tcp_header = packet[iph[0] & 0xF * 4 : iph[0] & 0xF * 4 + 20]
#             tcph = struct.unpack('!HHLLBBHHH', tcp_header)
#
#             # Extract the source and destination IP addresses and port numbers from the IP and TCP headers
#             src_ip = socket.inet_ntoa(iph[8])
#             dst_ip = socket.inet_ntoa(iph[9])
#             src_port = tcph[0]
#             dst_port = tcph[1]
#
#             # Check if this packet has the SYN flag set (i.e., the start of a new connection)
#             if tcph[5] & 2:
#                 # If it is the start of a new connection, initialize a new dictionary entry for this connection
#                 segments[(src_ip, dst_ip, src_port, dst_port)] = {}
#
#             # Check if this packet has any data (i.e., is not just an ACK packet)
#             if len(packet) > iph[0] & 0xF * 4 + tcph[4] * 4:
#                 # Extract the sequence number and payload data from the packet
#                 seq = tcph[2]
#                 payload = packet[iph[0] & 0xF * 4 + tcph[4] * 4:]
#
#                 # Add the payload data to the appropriate dictionary entry for this connection, based on the sequence number
#                 segments[(src_ip, dst_ip, src_port, dst_port)][seq] = payload
#
#             # Loop through the dictionary of TCP segments and concatenate them in order to reassemble the full TCP stream
#             for connection, seq_dict in segments.items():
#                 # Sort the dictionary of sequence numbers in ascending order
#                 sorted_seq_dict = dict(sorted(seq_dict.items()))
#
#                 # Concatenate the payload data from each segment in the sorted dictionary to reassemble the full TCP stream
#                 reassembled_data = b"".join(sorted_seq_dict.values())
#
#                 # Print the reassembled data for this connection
#                 print(f"Reassembled data for connection {connection}: {reassembled_data}")
#
#     # Close the socket
#     sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
#     sock.close()
#
# # Call the tcp_reassemble function to reassemble
