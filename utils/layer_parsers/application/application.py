from enum import Enum


class ApplicationType(Enum):

    HTTP = 80
    # HTTPS = 443   # TODO
    PFCP = 8805
    UNKNOWN = 0

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class ApplicationLayer:

    def __init__(self, application_type, application_data, src_port, dest_port):

        self._application_type = application_type
        self._application_data = application_data
        self._src_port = src_port
        self._dest_port = dest_port

    def _parse_data(self):
        # To be overwritten by child class
        pass

    def print_data(self):
        # To be overwritten by child class
        pass

    def print_raw_data(self):
        if self._application_data is not None and \
                len(self._application_data) > 0 and \
                not self.is_padding(self._application_data):
            print("Application Type: {}".format(self._application_type.name))
            print("Raw Data ({} bytes):".format(len(self._application_data)))
            print(self._application_data)
        return

    def is_padding(self, byte_string):
        for b in byte_string:
            if b != 0:
                return False
        return True

    @property
    def application_type(self):
        return self._application_type

    @property
    def application_data(self):
        return self._application_data
