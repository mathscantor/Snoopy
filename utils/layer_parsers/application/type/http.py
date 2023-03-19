from utils.layer_parsers.application.application import ApplicationType
from utils.layer_parsers.application.application import ApplicationLayer


class HTTP(ApplicationLayer):

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

        self._request_method = None
        self._request_uri = None
        self._request_version = None
        self._request_payload = None

        self._response_version = None
        self._response_status_code = None
        self._response_phrase = None
        self._response_payload = None
        self._parse_data()

    def _parse_data(self):
        if self._is_request and not self._is_response:
            self.__parse_request_data()
        elif self._is_response and not self._is_request:
            self.__parse_response_data()
        return

    def __parse_request_data(self):
        tokens = self._application_data[0:].decode('ISO-8859-1').splitlines()
        tmp = tokens[0].split(' ', 2)  # Eg. GET / HTTP/1.1
        self._request_method = tmp[0]
        self._request_uri = tmp[1]
        self._request_version = tmp[2]
        self._request_payload = tokens[3:]

    def __parse_response_data(self):
        tokens = self._application_data[0:].decode('ISO-8859-1').splitlines()
        tmp = tokens[0].split(' ', 2)  # Eg. HTTP/1.1 204 No Content
        self._response_version = tmp[0]
        self._response_status_code = tmp[1]
        self._response_phrase = tmp[2]
        self._response_payload = tokens[3:]

    def print_data(self):
        if self._is_request:
            self.__print_request_data()
        elif self._is_response:
            self.__print_response_data()

    def __print_request_data(self):
        print("\t+Request Method: {}\n,"
              "\t+Request URI: {}\n"
              "\t+Request Version: {}".format(self._request_method,
                                              self._request_uri,
                                              self._request_version))
        for i in range(len(self._request_payload)):
            if len(self._request_payload[i].strip()) == 0:
                if i + 1 < len(self._request_payload) and len(self._request_payload[i + 1:]) > 0:
                    print("\t+Payload: {}".format(''.join(self._request_payload[i + 1:])))
                    break
            else:
                print("\t+{}".format(self._request_payload[i].strip()))

    def __print_response_data(self):
        print("\t+Response Version: {}\n"
              "\t+Response Status Code: {}\n"
              "\t+Response Phrase: {}".format(self._response_version,
                                              self._response_status_code,
                                              self._response_phrase))
        for i in range(len(self._response_payload)):
            if len(self._response_payload[i].strip()) == 0:
                if i + 1 < len(self._response_payload) and len(
                        self._response_payload[i + 1:]) > 0:
                    print("\t+Payload: {}".format(''.join(self._response_payload[i + 1:])))
                    break
            else:
                print("\t+{}".format(self._response_payload[i].strip()))

    @property
    def request_method(self):
        return self._request_method

    @property
    def request_uri(self):
        return self._request_uri

    @property
    def request_version(self):
        return self._request_version

    @property
    def request_payload(self):
        return self._request_payload

    def response_payload(self):
        return self._response_payload

    @property
    def response_status_code(self):
        return self._response_status_code

    @property
    def response_phrase(self):
        return self._response_phrase

    @property
    def response_payload(self):
        return self._response_payload


