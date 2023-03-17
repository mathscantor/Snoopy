from utils.layer_parsers.transport.mappings import *
from utils.layer_parsers.transport.transport import TransportLayer
import struct


class SCTP(TransportLayer):

    def __init__(self, transport_type, transport_data):
        TransportLayer.__init__(self, transport_type, transport_data)
        self._verification_tag = None
        self._checksum = None
        self._chunk_type = None
        self._chunk_flags = None
        self._chunk_length = None
        self._parse_data()

    def _parse_data(self):
        self._src_port, self._dest_port, \
            self._verification_tag, self._checksum, \
            self._chunk_type, self._chunk_flags,\
            self._chunk_length = struct.unpack('! H H L L B B H', self._transport_data[:16])
        self._chunk_type = SCTPType(self._chunk_type)
        return

    def print_data(self):
        print("SCTP Data:")
        print("\t+Source Port: {}\n"
              "\t+Destination Port: {}\n"
              "\t+Verification Tag: {}\n"
              "\t+Checksum: {}\n"
              "\t+Chunk Type: {}\n"
              "\t+Chunk Flags: {}\n"
              "\t+Chunk Length: {}".format(self._src_port,
                                           self._dest_port,
                                           self._verification_tag,
                                           self._checksum,
                                           self._chunk_type.name,
                                           self._chunk_flags,
                                           self._chunk_length))
        return

    @property
    def verification_tag(self):
        return self._verification_tag

    @property
    def checksum(self):
        return self._checksum

    @property
    def chunk_type(self):
        return self._chunk_type

    @property
    def chunk_flags(self):
        return self._chunk_flags

    @property
    def chunk_length(self):
        return self._chunk_length
