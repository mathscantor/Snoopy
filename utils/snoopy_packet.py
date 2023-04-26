from utils.layer_parsers.link import *
from utils.layer_parsers.network import *
from utils.layer_parsers.transport import *
from utils.layer_parsers.application import *


class SnoopyPacket:

    def __init__(self, raw_data):

        self.__raw_data = raw_data
        self.__link_layer = None
        self.__network_layer = None
        self.__transport_layer = None
        self.__application_layer = None

        # ------------------ LINK LAYER ------------------ #
        self.__link_layer = self.__return_link_layer()
        if self.__link_layer.link_type == LinkType.UNKNOWN:
            return

        # ------------------ NETWORK LAYER ------------------ #
        self.__network_layer = self.__return_network_layer()
        if self.__network_layer.network_type == NetworkType.UNKNOWN:
            return

        # ------------------ TRANSPORT LAYER ------------------ #
        self.__transport_layer = self.__return_transport_layer()
        if self.__transport_layer.transport_type == TransportType.UNKNOWN:
            return

        # ------------------ APPLICATION LAYER ------------------ #
        self.__application_layer = self.__return_application_layer()

        return

    def __return_link_layer(self):
        link_type = LinkType(0x01)
        if link_type == LinkType.UNKNOWN:
            return LinkLayer(link_type=link_type,
                             link_data=self._raw_data)
        elif link_type == LinkType.ETHER:
            return Ether(link_type=link_type,
                         link_data=self.__raw_data)
        return None

    def __return_network_layer(self):
        if self.__link_layer.network_type == NetworkType.UNKNOWN:
            return NetworkLayer(network_type=self.__link_layer.network_type,
                                network_data=self.__link_layer.network_data)
        elif self.__link_layer.network_type == NetworkType.IPV4:
            return IPv4(network_type=self.__link_layer.network_type,
                        network_data=self.__link_layer.network_data)
        elif self.__link_layer.network_type == NetworkType.IPV6:
            return IPv6(network_type=self.__link_layer.network_type,
                        network_data=self.__link_layer.network_data)
        return None

    def __return_transport_layer(self):
        if self.__network_layer.transport_type == TransportType.UNKNOWN:
            return TransportLayer(transport_type=self.__network_layer.transport_type,
                                  transport_data=self.__network_layer.transport_data)
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
        return None

    def __return_application_layer(self):

        if self.__transport_layer.application_type == ApplicationType.UNKNOWN:
            return ApplicationLayer(application_type=self.__transport_layer.application_type,
                                    application_data=self.__transport_layer.application_data,
                                    src_port=self.__transport_layer.src_port,
                                    dest_port=self.__transport_layer.dest_port)

        elif self.__transport_layer.application_type == ApplicationType.HTTP:
            return HTTP(application_type=self.__transport_layer.application_type,
                        application_data=self.__transport_layer.application_data,
                        src_port=self.__transport_layer.src_port,
                        dest_port=self.__transport_layer.dest_port)
        # elif self.__transport_layer.application_type == ApplicationType.HTTPS:
        #     return HTTPS(application_type=self.__transport_layer.application_type,
        #                  application_data=self.__transport_layer.application_data,
        #                  src_port=self.__transport_layer.src_port,
        #                  dest_port=self.__transport_layer.dest_port)
        elif self.__transport_layer.application_type == ApplicationType.PFCP:
            return PFCP(application_type=self.__transport_layer.application_type,
                        application_data=self.__transport_layer.application_data,
                        src_port=self.__transport_layer.src_port,
                        dest_port=self.__transport_layer.dest_port)
        return None

    def print_packet_verbose(self):
        if self.__link_layer is None:
            return
        if self.__link_layer.link_type == LinkType.UNKNOWN:
            self.__link_layer.print_raw_data()
            return
        self.__link_layer.print_data()

        if self.__network_layer is None:
            return
        if self.__network_layer.network_type == NetworkType.UNKNOWN:
            self.__network_layer.print_raw_data()
            return
        self.__network_layer.print_data()

        if self.__transport_layer is None:
            return
        if self.__transport_layer.transport_type == TransportType.UNKNOWN:
            self.__transport_layer.print_raw_data()
            return
        self.__transport_layer.print_data()

        if self.__application_layer is None:
            return
        if self.__application_layer.application_type == ApplicationType.UNKNOWN:
            self.__application_layer.print_raw_data()
            return
        self.__application_layer.print_data()
        return

    def print_packet_minimal(self):
        packet_info = "Raw({} bytes)".format(len(self.__raw_data))
        if self.__link_layer is None:
            print(packet_info)
            return
        packet_info = "{}(Src MAC: {}, Dst MAC: {})".format(self.__link_layer.link_type.name,
                                                            self.__link_layer.src_mac,
                                                            self.__link_layer.dest_mac)
        if self.__link_layer.vlan_type is not None:
            packet_info += " / {}(Priority: {}, DEI: {}, ID: {})".format(self.__link_layer.vlan_type.name,
                                                                         self.__link_layer.vlan_priority,
                                                                         self.__link_layer.vlan_dei,
                                                                         self.__link_layer.vlan_id)
        if self.__network_layer is None:
            return
        if self.__network_layer.network_type == NetworkType.UNKNOWN and len(self.__network_layer.network_data) > 0:
            packet_info += " / Raw({} bytes)".format(len(self.__network_layer.network_data))
            print(packet_info)
            return
        packet_info += " / {}(Src IP: {}, Dst IP: {})".format(self.__network_layer.network_type.name,
                                                              self.__network_layer.src_ip,
                                                              self.__network_layer.dest_ip)

        if self.__transport_layer is None:
            return
        if self.__transport_layer.transport_type == TransportType.UNKNOWN and len(self.__transport_layer.transport_data) > 0:
            packet_info += " / Raw({} bytes)".format(len(self.__network_layer.transport_data))
            print(packet_info)
            return
        packet_info += " / {}(Src Port: {}, Dst Port: {})".format(self.__transport_layer.transport_type.name,
                                                                  self.__transport_layer.src_port,
                                                                  self.__transport_layer.dest_port)

        if self.__application_layer is None:
            return
        if self.__application_layer.application_type == ApplicationType.UNKNOWN and len(self.__application_layer.application_data) > 0:
            packet_info += " / Raw({} bytes)".format(len(self.__application_layer.application_data))
            print(packet_info)
            return
        packet_info += " / {}({} bytes)".format(self.__application_layer.application_type.name,
                                                len(self.__application_layer.application_data))
        print(packet_info)
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


