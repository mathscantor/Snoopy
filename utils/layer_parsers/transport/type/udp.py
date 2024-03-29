from utils.layer_parsers.application.application import ApplicationType
from utils.layer_parsers.transport.transport import TransportLayer
import struct


class UDP(TransportLayer):

    def __init__(self, transport_type, transport_data):
        TransportLayer.__init__(self, transport_type, transport_data)
        self._length = None
        self._checksum = None
        self._parse_data()

    def _parse_data(self):
        # UDP header length is always 8 bytes
        self._src_port, self._dest_port, \
            self._length, self._checksum = struct.unpack('! H H H H', self._transport_data[:8])
        self._application_data = self._transport_data[8:]

        if len(self._application_data) == 0:
            return

        if self.is_padding(self._application_data):
            return

        self._application_type = ApplicationType(self._src_port)
        if self._application_type == ApplicationType.UNKNOWN:
            self._application_type = ApplicationType(self._dest_port)

        return

    def print_data(self):
        print("UDP Data:")
        print("\t+Source Port: {}\n"
              "\t+Destination Port: {}\n"
              "\t+Length: {}\n"
              "\t+Checksum: {}".format(self._src_port,
                                       self._dest_port,
                                       self._length,
                                       self._checksum))
        if self._application_type is not None:
            print("\t+Application Type: {}".format(self._application_type.name))
        return

    @property
    def length(self) -> int:
        return self._length

    @property
    def checksum(self) -> int:
        return self._checksum
