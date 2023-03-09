from utils.layer_parsers.network.mappings import *
from utils.layer_parsers.transport.mappings import *
import struct


class TransportLayer:

    def __init__(self, transport_type, transport_data):

        self.__transport_type = transport_type
        if self.__transport_type == TransportType.UNKNOWN:
            print("Error in transport type! Unable to do parsing in utils/layer_parsers/transport.py!")
            print("Exiting...")
            exit(1)

        self.__transport_data = transport_data
        self.__application_type = None
        self.__application_data = None
        # Transport Data
        # ICMP
        self.__icmp_type = None
        self.__icmp_code = None
        self.__icmp_checksum = None

        self.__src_port = None
        self.__dest_port = None

        # SCTP
        self.__sctp_verification_tag = None
        self.__sctp_checksum = None
        self.__sctp_chunk_type = None
        self.__sctp_chunk_flags = None
        self.__sctp_chunk_length = None

        # UDP
        self.__udp_length = None
        self.__udp_checksum = None

        # TCP
        self.__tcp_sequence = None
        self.__tcp_acknowledgement = None
        self.__tcp_header_length = None
        self.__tcp_flag_urg = None
        self.__tcp_flag_ack = None
        self.__tcp_flag_psh = None
        self.__tcp_flag_rst = None
        self.__tcp_flag_syn = None
        self.__tcp_flag_fin = None

        self.parse_transport_data()
        return

    def is_padding(self, byte_string):
        for b in byte_string:
            if b != 0:
                return False
        return True

    def parse_transport_data(self):
        if self.__transport_type == TransportType.ICMP:
            self.__parse_icmp_data()
        elif self.__transport_type == TransportType.TCP:
            self.__parse_tcp_data()
        elif self.__transport_type == TransportType.UDP:
            self.__parse_udp_data()
        elif self.__transport_type == TransportType.SCTP:
            self.__parse_sctp_data()

    def __parse_icmp_data(self):
        self.__icmp_type, self.__icmp_code, self.__icmp_checksum = struct.unpack('! B B H', self.__transport_data[:4])
        return

    def __parse_tcp_data(self):
        self.__src_port, \
            self.__dest_port, self.__tcp_sequence, \
            self.__tcp_acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H',
                                                                       self.__transport_data[:14])
        self.__tcp_header_length = (offset_reserved_flags >> 12) * 4
        self.__tcp_flag_urg = (offset_reserved_flags & 32) >> 5
        self.__tcp_flag_ack = (offset_reserved_flags & 16) >> 4
        self.__tcp_flag_psh = (offset_reserved_flags & 8) >> 3
        self.__tcp_flag_rst = (offset_reserved_flags & 4) >> 2
        self.__tcp_flag_syn = (offset_reserved_flags & 2) >> 1
        self.__tcp_flag_fin = offset_reserved_flags & 1
        self.__application_data = self.__transport_data[self.__tcp_header_length:]

        if len(self.__application_data) == 0:
            return

        if self.is_padding(self.__application_data):
            return

        self.__application_type = ApplicationType(self.__src_port)
        if self.__application_type != ApplicationType.UNKNOWN:
            return

        self.__application_type = ApplicationType(self.__dest_port)
        return

    def __parse_udp_data(self):
        # UDP header length is always 8 bytes
        self.__src_port, self.__dest_port, \
            self.__udp_length, self.__udp_checksum = struct.unpack('! H H H H', self.__transport_data[:8])
        self.__application_data = self.__transport_data[8:]

        if len(self.__application_data) == 0:
            return

        if self.is_padding(self.__application_data):
            return

        self.__application_type = ApplicationType(self.__src_port)
        if self.__application_type != ApplicationType.UNKNOWN:
            return

        self.__application_type = ApplicationType(self.__dest_port)
        return

    def __parse_sctp_data(self):
        self.__src_port, self.__dest_port, \
            self.__sctp_verification_tag, self.__sctp_checksum, \
            self.__sctp_chunk_type, self.__sctp_chunk_flags,\
            self.__sctp_chunk_length = struct.unpack('! H H L L B B H', self.__transport_data[:16])
        self.__sctp_chunk_type = SCTPType(self.__sctp_chunk_type)
        return

    def get_application_type(self):
        return self.__application_type

    def get_application_data(self):
        return self.__application_data

    def get_icmp_type(self):
        return self.__icmp_type

    def get_icmp_code(self):
        return self.__icmp_code

    def get_icmp_checksum(self):
        return self.__icmp_checksum

    def get_src_port(self):
        return self.__src_port

    def get_dest_port(self):
        return self.__dest_port

    def get_tcp_sequence(self):
        return self.__tcp_sequence

    def get_tcp_acknowledgement(self):
        return self.__tcp_acknowledgement

    def get_tcp_header_length(self):
        return self.__tcp_header_length

    def get_tcp_flag_urg(self):
        return self.__tcp_flag_urg

    def get_tcp_flag_ack(self):
        return self.__tcp_flag_ack

    def get_tcp_flag_psh(self):
        return self.__tcp_flag_ack

    def get_tcp_flag_rst(self):
        return self.__tcp_flag_rst

    def get_tcp_flag_syn(self):
        return self.__tcp_flag_syn

    def get_tcp_flag_fin(self):
        return self.__tcp_flag_fin

    def print_transport_payload(self):
        if self.__application_data is not None and \
                len(self.__application_data) > 0 and \
                not self.is_padding(self.__application_data):
            print("Transport Payload ({} bytes):".format(len(self.__application_data)))
            print(self.__application_data)
        return

    def print_transport_data(self):
        if self.__transport_type == TransportType.ICMP:
            self.__print_icmp_data()
        elif self.__transport_type == TransportType.TCP:
            self.__print_tcp_data()
        elif self.__transport_type == TransportType.UDP:
            self.__print_udp_data()
        elif self.__transport_type == TransportType.SCTP:
            self.__print_sctp_data()

    def __print_icmp_data(self):
        print("ICMP Data:")
        print("\t+Type: {}\n"
              "\t+Code: {}\n"
              "\t+Checksum: {}".format(self.__icmp_type,
                                       self.__icmp_code,
                                       self.__icmp_checksum))
        return

    def __print_tcp_data(self):
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
              "\t\t+FIN: {}".format(self.__src_port,
                                    self.__dest_port,
                                    self.__tcp_sequence,
                                    self.__tcp_acknowledgement,
                                    self.__tcp_header_length,
                                    self.__tcp_flag_urg,
                                    self.__tcp_flag_ack,
                                    self.__tcp_flag_psh,
                                    self.__tcp_flag_rst,
                                    self.__tcp_flag_syn,
                                    self.__tcp_flag_fin))

        if self.__application_type is not None and len(self.__application_data) > 0:
            print("\t+Application Type: {}".format(self.__application_type.name))
        return

    def __print_udp_data(self):

        print("UDP Data:")
        print("\t+Source Port: {}\n"
              "\t+Destination Port: {}\n"
              "\t+Length: {}\n"
              "\t+Checksum: {}".format(self.__src_port,
                                       self.__dest_port,
                                       self.__udp_length,
                                       self.__udp_checksum))

        if self.__application_type is not None and len(self.__application_data) > 0:
            print("\t+Application Type: {}".format(self.__application_type.name))
        return

    def __print_sctp_data(self):
        print("SCTP Data:")
        print("\t+Source Port: {}\n"
              "\t+Destination Port: {}\n"
              "\t+Verification Tag: {}\n"
              "\t+Checksum: {}\n"
              "\t+Chunk Type: {}\n"
              "\t+Chunk Flags: {}\n"
              "\t+Chunk Length: {}".format(self.__src_port,
                                           self.__dest_port,
                                           self.__sctp_verification_tag,
                                           self.__sctp_checksum,
                                           self.__sctp_chunk_type.name,
                                           self.__sctp_chunk_flags,
                                           self.__sctp_chunk_length))
        return

