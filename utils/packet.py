from utils.layer_parsers.link.mappings import *
from utils.layer_parsers.network.mappings import *
from utils.layer_parsers.transport.mappings import *

from utils.layer_parsers.link import *
from utils.layer_parsers.network import *
from utils.layer_parsers.transport import *
from utils.layer_parsers.application.application import ApplicationLayer


class Packet:

    def __init__(self, raw_data):

        self.__raw_data = raw_data
        self.__link_layer = None
        self.__network_layer = None
        self.__transport_layer = None
        self.__application_layer = None

        # ------------------ LINK LAYER ------------------ #
        self.__link_layer = self.__return_link_layer()
        if self.__link_layer is None:
            return

        # ------------------ NETWORK LAYER ------------------ #
        self.__network_layer = self.__return_network_layer()
        self.__network_layer.print_data()
        if self.__network_layer is None:
            return

        # ------------------ TRANSPORT LAYER ------------------ #
        self.__transport_layer = self.__return_transport_layer()
        if self.__transport_layer is None:
            return

        if self.__transport_layer.application_type == ApplicationType.UNKNOWN:
            return
        if self.__transport_layer.application_data is None:
            return
        if len(self.__transport_layer.application_data) == 0:
            return

        # ------------------ APPLICATION LAYER ------------------ #
        self.__application_layer = ApplicationLayer(application_type=self.__transport_layer.application_type,
                                                    application_data=self.__transport_layer.application_data,
                                                    src_port=self.__transport_layer.src_port,
                                                    dest_port=self.__transport_layer.dest_port)
        return

    def __return_link_layer(self):
        return Ether(raw_data=self.__raw_data)

    def __return_network_layer(self):
        if self.__link_layer.network_type == NetworkType.UNKNOWN:
            return None

        elif self.__link_layer.network_type == NetworkType.IPV4:
            return IPv4(network_type=self.__link_layer.network_type,
                        network_data=self.__link_layer.network_data)

        elif self.__link_layer.network_type == NetworkType.IPV6:
            return IPv6(network_type=self.__link_layer.network_type,
                        network_data=self.__link_layer.network_data)

    def __return_transport_layer(self):
        if self.__network_layer.transport_type == TransportType.UNKNOWN:
            return None

        elif self.__network_layer.transport_type == TransportType.ICMP:
            return ICMP(transport_type=self.__network_layer.transport_type,
                        transport_data=self.__network_layer.transport_data)

        elif self.__network_layer.transport_type == TransportType.SCTP:
            return SCTP(transport_type=self.__network_layer.transport_type,
                        transport_data=self.__network_layer.transport_data)

        elif self.__network_layer.transport_type == TransportType.TCP:
            return TCP(transport_type=self.__network_layer.transport_type,
                       transport_data=self.__network_layer.transport_data)

        elif self.__network_layer.transport_type == TransportType.UDP:
            return UDP(transport_type=self.__network_layer.transport_type,
                       transport_data=self.__network_layer.transport_data)

    def print_packet(self):
        self.__link_layer.print_data()
        if self.__link_layer.network_type == NetworkType.UNKNOWN or \
                self.__link_layer.network_type is None:
            self.__link_layer.print_raw_network_data()
            return

        self.__network_layer.print_data()
        if self.__network_layer.transport_type == TransportType.UNKNOWN or \
                self.__network_layer.transport_type is None:
            self.__network_layer.print_raw_transport_data()
            return

        self.__transport_layer.print_data()
        if self.__transport_layer.application_type == ApplicationType.UNKNOWN or \
                self.__transport_layer.application_type is None:
            self.__transport_layer.print_transport_payload()
            return
        if self.__transport_layer.application_data is None:
            return
        if len(self.__transport_layer.application_data) == 0:
            return

        self.__application_layer.print_application_data()
        return

    @property
    def raw_data(self):
        return self.__raw_data

    @property
    def link_layer(self):
        return self.__link_layer

    @property
    def network_layer(self):
        return self.__network_layer

    @property
    def transport_layer(self):
        return self.__transport_layer

    @property
    def application_layer(self):
        return self.__application_layer


