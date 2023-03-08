from utils.mappings import *
from utils.layers.link import LinkLayer
from utils.layers.network import NetworkLayer
from utils.layers.transport import TransportLayer
from utils.layers.application import ApplicationLayer


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

        # ------------------ APPLICATION LAYER ------------------ #
        self.__application_layer = ApplicationLayer(application_type=self.__transport_layer.get_application_type(),
                                                    application_data=self.__transport_layer.get_application_data())
        return

    def get_link_layer(self):
        return self.__link_layer

    def get_network_layer(self):
        return self.__network_layer

    def get_transport_layer(self):
        return self.__transport_layer

    def print_packet(self):
        self.__link_layer.print_link_data()
        self.__network_layer.print_network_data()
        self.__transport_layer.print_transport_data()

