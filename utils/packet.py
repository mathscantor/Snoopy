from utils.layer_parsers.link.mappings import *
from utils.layer_parsers.network.mappings import *
from utils.layer_parsers.transport.mappings import *
from utils.layer_parsers.link.link import LinkLayer
from utils.layer_parsers.network.network import NetworkLayer
from utils.layer_parsers.transport.transport import TransportLayer
from utils.layer_parsers.application.application import ApplicationLayer


class Packet:

    def __init__(self, raw_data):

        # ------------------ LINK LAYER ------------------ #
        self.__link_layer = LinkLayer(raw_data=raw_data)
        if self.__link_layer.get_network_type() == NetworkType.UNKNOWN:
            return

        # ------------------ NETWORK LAYER ------------------ #
        self.__network_layer = NetworkLayer(network_type=self.__link_layer.get_network_type(),
                                            network_data=self.__link_layer.get_network_data())

        if self.__network_layer.get_transport_type() == TransportType.UNKNOWN:
            return

        # ------------------ TRANSPORT LAYER ------------------ #
        self.__transport_layer = TransportLayer(transport_type=self.__network_layer.get_transport_type(),
                                                transport_data=self.__network_layer.get_transport_data())

        if self.__transport_layer.get_application_type() == ApplicationType.UNKNOWN:
            return
        if self.__transport_layer.get_application_data() is None:
            return
        if len(self.__transport_layer.get_application_data()) == 0:
            return

        # ------------------ APPLICATION LAYER ------------------ #
        self.__application_layer = ApplicationLayer(application_type=self.__transport_layer.get_application_type(),
                                                    application_data=self.__transport_layer.get_application_data(),
                                                    src_port=self.__transport_layer.get_src_port(),
                                                    dest_port=self.__transport_layer.get_dest_port())
        return

    def get_link_layer(self):
        return self.__link_layer

    def get_network_layer(self):
        return self.__network_layer

    def get_transport_layer(self):
        return self.__transport_layer

    def print_packet(self):
        self.__link_layer.print_link_data()
        if self.__link_layer.get_network_type() == NetworkType.UNKNOWN or \
                self.__link_layer.get_network_type() is None:
            self.__link_layer.print_raw_network_data()
            return

        self.__network_layer.print_network_data()
        if self.__network_layer.get_transport_type() == TransportType.UNKNOWN or \
                self.__network_layer.get_transport_type() is None:
            self.__network_layer.print_raw_transport_data()
            return

        self.__transport_layer.print_transport_data()
        if self.__transport_layer.get_application_type() == ApplicationType.UNKNOWN or \
                self.__transport_layer.get_application_type() is None:
            self.__transport_layer.print_transport_payload()
            return
        if self.__transport_layer.get_application_data() is None:
            return
        if len(self.__transport_layer.get_application_data()) == 0:
            return

        self.__application_layer.print_application_data()
        return

