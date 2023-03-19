from utils.layer_parsers.application.application import ApplicationType
from utils.layer_parsers.application.application import ApplicationLayer


class HTTPS(ApplicationLayer):

    def __init__(self, application_type, application_data, src_port, dest_port):
        ApplicationLayer.__init__(self, application_type, application_data, src_port, dest_port)

        self._is_request = False
        self._is_response = False

        if ApplicationType(self._dest_port) == ApplicationType.HTTP:
            self._is_request = True
            self._is_response = False

        elif ApplicationType(self._src_port) == ApplicationType.HTTP:
            self._is_request = False
            self._is_response = True

        self._parse_data()

    def _parse_data(self):
        if self._is_request and not self._is_response:
            self.__parse_request_data()
        elif self._is_response and not self._is_request:
            self.__parse_response_data()
        return

    def __parse_request_data(self):
        return

    def __parse_response_data(self):
        return

    def print_data(self):
        if self._is_request:
            self.__print_request_data()
        elif self._is_response:
            self.__print_response_data()
        return

    def __print_request_data(self):
        return

    def __print_response_data(self):
        return
