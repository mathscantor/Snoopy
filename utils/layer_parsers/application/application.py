from enum import Enum


class ApplicationType(Enum):

    HTTP = 80
    HTTPS = 443
    PFCP = 8805
    UNKNOWN = 0

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class ApplicationLayer:

    def __init__(self, application_type, application_data, src_port, dest_port):

        self._application_type = application_type
        if self._application_type == ApplicationType.UNKNOWN:
            print("Error in application type! Unable to do parsing in utils/layer_parsers/application.py!")
            print("Exiting...")
            exit(1)
        self._application_data = application_data
        self._src_port = src_port
        self._dest_port = dest_port

    def _parse_data(self):
        # To be overwritten by child class
        pass

    def print_data(self):
        # To be overwritten by child class
        pass

    @property
    def application_type(self):
        return self._application_type

    @property
    def application_data(self):
        return self._application_data
