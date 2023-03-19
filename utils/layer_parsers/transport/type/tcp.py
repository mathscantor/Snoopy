from utils.layer_parsers.application.application import ApplicationType
from utils.layer_parsers.transport.transport import TransportLayer
import struct


class TCP(TransportLayer):

    def __init__(self, transport_type, transport_data):
        TransportLayer.__init__(self, transport_type, transport_data)
        self._sequence = None
        self._acknowledgement = None
        self._header_length = None
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
            self._acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H',
                                                                         self._transport_data[:14])
        self._header_length = (offset_reserved_flags >> 12) * 4
        self._flag_urg = (offset_reserved_flags & 32) >> 5
        self._flag_ack = (offset_reserved_flags & 16) >> 4
        self._flag_psh = (offset_reserved_flags & 8) >> 3
        self._flag_rst = (offset_reserved_flags & 4) >> 2
        self._flag_syn = (offset_reserved_flags & 2) >> 1
        self._flag_fin = offset_reserved_flags & 1
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
              "\t\t+FIN: {}".format(self._src_port,
                                    self._dest_port,
                                    self._sequence,
                                    self._acknowledgement,
                                    self._header_length,
                                    self._flag_urg,
                                    self._flag_ack,
                                    self._flag_psh,
                                    self._flag_rst,
                                    self._flag_syn,
                                    self._flag_fin))

        if self._application_type is not None and len(self._application_data) > 0:
            print("\t+Application Type: {}".format(self._application_type.name))
        return

    @property
    def sequence(self):
        return self._sequence

    @property
    def acknowledgement(self):
        return self._acknowledgement

    @property
    def header_length(self):
        return self._header_length

    @property
    def flag_urg(self):
        return self._flag_urg

    @property
    def flag_ack(self):
        return self._flag_ack

    @property
    def flag_psh(self):
        return self._flag_psh

    @property
    def flag_rst(self):
        return self._flag_rst

    @property
    def flag_syn(self):
        return self._flag_syn

    @property
    def flag_fin(self):
        return self._flag_fin
