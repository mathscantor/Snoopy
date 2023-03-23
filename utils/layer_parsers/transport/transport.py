from enum import Enum


class TransportType(Enum):
    ICMP = 0x01
    TCP = 0x06
    UDP = 0x11
    SCTP = 0x84
    UNKNOWN = 0xff

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class TransportLayer:

    def __init__(self, transport_type, transport_data):

        self._transport_type = transport_type
        if self._transport_type == TransportType.UNKNOWN:
            print("Error in transport type! Unable to do parsing in utils/layer_parsers/transport.py!")
            print("Exiting...")
            exit(1)

        self._transport_data = transport_data
        self._application_type = None
        self._application_data = None
        self._src_port = None
        self._dest_port = None
        return

    def _parse_data(self):
        # To be overwritten by child class
        pass

    def print_data(self):
        # To be overwritten by child class
        pass

    def print_transport_payload(self):
        if self._application_data is not None and \
                len(self._application_data) > 0 and \
                not self.is_padding(self._application_data):
            print("Transport Payload ({} bytes):".format(len(self._application_data)))
            print(self._application_data)
        return

    def is_padding(self, byte_string):
        for b in byte_string:
            if b != 0:
                return False
        return True

    @property
    def transport_type(self):
        return self._transport_type

    @property
    def transport_data(self):
        return self._transport_data

    @property
    def application_type(self):
        return self._application_type

    @property
    def application_data(self):
        return self._application_data

    @property
    def src_port(self):
        return self._src_port

    @property
    def dest_port(self):
        return self._dest_port


