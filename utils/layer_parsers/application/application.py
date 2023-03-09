from utils.layer_parsers.transport.mappings import *
from utils.layer_parsers.application.mappings import *
import struct


class ApplicationLayer:

    def __init__(self, application_type, application_data, src_port, dest_port):

        self.__application_type = application_type
        if self.__application_type == ApplicationType.UNKNOWN:
            print("Error in application type! Unable to do parsing in utils/layer_parsers/application.py!")
            print("Exiting...")
            exit(1)
        self.__application_data = application_data
        self.__src_port = src_port
        self.__dest_port = dest_port

        # HTTP
        ## REQUEST
        self.__http_request_method = None
        self.__http_request_uri = None
        self.__http_request_version = None
        self.__http_request_host = None
        self.__http_request_user_agent = None
        self.__http_request_accept = None
        self.__http_request_accept_language = None
        self.__http_request_accept_encoding = None
        self.__http_request_cache_control = None
        self.__http_request_pragma = None
        self.__http_request_connection = None
        ## RESPONSE
        self.__http_response_version = None
        self.__http_response_status_code = None
        self.__http_response_phrase = None
        self.__http_response_server = None
        self.__http_response_date = None
        self.__http_response_x_networkmanager_status = None
        self.__http_response_connection = None


        # PFCP
        self.__pfcp_flags = None
        self.__pfcp_flag_version = None
        self.__pfcp_flag_spare1 = None
        self.__pfcp_flag_spare2 = None
        self.__pfcp_flag_follow_on = None
        self.__pfcp_flag_message_priority = None
        self.__pfcp_flag_seid = None
        self.__pfcp_message_type = None
        self.__pfcp_length = None
        self.__pfcp_seid = None
        self.__pfcp_sequence_number = None
        self.__pfcp_spare = None

        self.parse_application_data()
        return

    def parse_application_data(self):
        if self.__application_type == ApplicationType.HTTP:
            self.__parse_http_data()
            return
        if self.__application_type == ApplicationType.HTTPS:
            self.__parse_https_data()
            return
        if self.__application_type == ApplicationType.PFCP:
            self.__parse_pfcp_data()
            return

    def __parse_http_data(self):
        # REQUEST
        if self.__dest_port == ApplicationType.HTTP.value:
            tokens = self.__application_data[0:].decode('ISO-8859-1').splitlines()
            tmp = tokens[0].split(' ', 2)  # Eg. GET / HTTP/1.1
            self.__http_request_method = tmp[0]
            self.__http_request_uri = tmp[1]
            self.__http_request_version = tmp[2]
            self.__http_request_greedy_data = tokens[3:]


        # RESPONSE
        elif self.__src_port == ApplicationType.HTTP.value:
            tokens = self.__application_data[0:].decode('ISO-8859-1').splitlines()
            tmp = tokens[0].split(' ', 2) # Eg. HTTP/1.1 204 No Content
            self.__http_response_version = tmp[0]
            self.__http_response_status_code = tmp[1]
            self.__http_response_phrase = tmp[2]
            self.__http_response_greedy_data = tokens[3:]

        return

    def __parse_https_data(self):
        return

    def __parse_pfcp_data(self):
        self.__pfcp_flags = self.__application_data[0]
        self.__pfcp_flag_version = self.__pfcp_flags >> 5
        self.__pfcp_flag_spare1 = self.__pfcp_flags >> 4
        self.__pfcp_flag_spare2 = self.__pfcp_flags >> 3
        self.__pfcp_flag_follow_on = self.__pfcp_flags >> 2
        self.__pfcp_flag_message_priority = self.__pfcp_flags >> 1
        self.__pfcp_flag_seid = self.__pfcp_flags & 1

        if self.__pfcp_flag_seid == 1:
            self.__pfcp_message_type, self.__pfcp_length,\
               self.__pfcp_seid,  self.__pfcp_sequence_number,\
               self.__pfcp_spare = struct.unpack('! B H Q 3s B', self.__application_data[1:])
        else:
            self.__pfcp_message_type, self.__pfcp_length,\
                self.__pfcp_sequence_number, self.__pfcp_spare = struct.unpack('! B H 3s B', self.__application_data[1:8])

        self.__pfcp_message_type = PFCPType(self.__pfcp_message_type)
        self.__pfcp_sequence_number = int.from_bytes(self.__pfcp_sequence_number, 'big')
        return

    def print_application_data(self):
        if self.__application_type == ApplicationType.HTTP:
            self.__print_http_data()
            return
        if self.__application_type == ApplicationType.HTTPS:
            self.__print_https_data()
            return
        if self.__application_type == ApplicationType.PFCP:
            self.__print_pfcp_data()
            return
        return

    def __print_http_data(self):
        print("HTTP Data:")
        # REQUEST
        if self.__dest_port == ApplicationType.HTTP.value:
            print("\t+Request Method: {}\n,"
                  "\t+Request URI: {}\n"
                  "\t+Request Version: {}".format(self.__http_request_method,
                                            self.__http_request_uri,
                                            self.__http_request_version))
            for i in range(len(self.__http_request_greedy_data)):
                if len(self.__http_request_greedy_data[i].strip()) == 0:
                    if i+1 < len(self.__http_request_greedy_data) and len(self.__http_request_greedy_data[i+1:]) > 0:
                        print("\t+Payload: {}".format(''.join(self.__http_request_greedy_data[i+1:])))
                        break
                else:
                    print("\t+{}".format(self.__http_request_greedy_data[i].strip()))

        # RESPONSE
        elif self.__src_port == ApplicationType.HTTP.value:
            print("\t+Response Version: {}\n"
                  "\t+Response Status Code: {}\n"
                  "\t+Response Phrase: {}".format(self.__http_response_version,
                                                  self.__http_response_status_code,
                                                  self.__http_response_phrase))
            for i in range(len(self.__http_response_greedy_data)):
                if len(self.__http_response_greedy_data[i].strip()) == 0:
                    if i + 1 < len(self.__http_response_greedy_data) and len(
                            self.__http_response_greedy_data[i + 1:]) > 0:
                        print("\t+Payload: {}".format(''.join(self.__http_response_greedy_data[i + 1:])))
                        break
                else:
                    print("\t+{}".format(self.__http_response_greedy_data[i].strip()))
        return

    def __print_https_data(self):
        return

    def __print_pfcp_data(self):
        print("PFCP Data:")
        print("\t+Flags: {}\n"
              "\t+Message Type: {}\n"
              "\t+Length: {}\n"
              "\t+Sequence Number: {}\n"
              "\t+Spare: {}".format(self.__pfcp_flags,
                                    self.__pfcp_message_type.name,
                                    self.__pfcp_length,
                                    self.__pfcp_sequence_number,
                                    self.__pfcp_spare))
        return
