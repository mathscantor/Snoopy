import socket
from utils.snoopy_packet import SnoopyPacket
import gc
import argparse
from utils.pcapng_saver import PcapngSaver
from utils.layer_parsers.link import *
from utils.layer_parsers.network import *
from utils.layer_parsers.transport import *
from utils.layer_parsers.application import *
from scapy.all import *


def is_duplicate_packet(raw_data: bytes) -> bool:
    is_duplicate = False
    if raw_data in packets_set:
        is_duplicate = True

    if len(packets_set) > 1000:
        packets_set.clear()

    return is_duplicate


def is_packet_of_interest(snoopy_packet: SnoopyPacket) -> bool:
    # No Filters specified, then return True
    if not has_network_filter and not has_transport_filter and not has_application_filter:
        return True

    # --network ...
    elif has_network_filter and not has_transport_filter and not has_application_filter:
        if snoopy_packet.network_layer is None or snoopy_packet.network_layer.network_type is None:
            return False
        if snoopy_packet.network_layer.network_type.name in args.network_include:
            return True

    # --network ... --transport ...
    elif has_network_filter and has_transport_filter and not has_application_filter:
        if snoopy_packet.network_layer is None or snoopy_packet.network_layer.network_type is None:
            return False
        if snoopy_packet.transport_layer is None or snoopy_packet.transport_layer.transport_type is None:
            return False
        if snoopy_packet.network_layer.network_type.name in args.network_include \
                and snoopy_packet.transport_layer.transport_type.name in args.transport_include:
            return True

    # --network ... --application ...
    elif has_network_filter and not has_transport_filter and has_application_filter:
        if snoopy_packet.network_layer is None or snoopy_packet.network_layer.network_type is None:
            return False
        if snoopy_packet.transport_layer is None or snoopy_packet.transport_layer.transport_type is None:
            return False
        if snoopy_packet.application_layer is None or snoopy_packet.application_layer.application_type is None:
            return False
        if snoopy_packet.network_layer.network_type.name in args.network_include \
                and snoopy_packet.application_layer.application_type.name in args.application_include:
            return True

    elif has_network_filter and has_transport_filter and has_application_filter:
        if snoopy_packet.network_layer is None or snoopy_packet.network_layer.network_type is None:
            return False
        if snoopy_packet.transport_layer is None or snoopy_packet.transport_layer.transport_type is None:
            return False
        if snoopy_packet.application_layer is None or snoopy_packet.application_layer.application_type is None:
            return False
        if snoopy_packet.network_layer.network_type.name in args.network_include \
                and snoopy_packet.transport_layer.transport_type.name in args.transport_include \
                and snoopy_packet.application_layer.application_type.name in args.application_include:
            return True

    # --transport ...
    elif not has_network_filter and has_transport_filter and not has_application_filter:
        if snoopy_packet.transport_layer is None or snoopy_packet.transport_layer.transport_type is None:
            return False
        if snoopy_packet.transport_layer.transport_type.name in args.transport_include:
            return True

    # --application ...
    elif not has_network_filter and not has_transport_filter and has_application_filter:
        if snoopy_packet.transport_layer is None or snoopy_packet.transport_layer.transport_type is None:
            return False
        if snoopy_packet.application_layer is None or snoopy_packet.application_layer.application_type is None:
            return False
        if snoopy_packet.application_layer.application_type.name in args.application_include:
            return True

    # --transport ... --application ...
    elif not has_network_filter and has_transport_filter and has_application_filter:
        if snoopy_packet.transport_layer is None or snoopy_packet.transport_layer.transport_type is None:
            return False
        if snoopy_packet.application_layer is None or snoopy_packet.application_layer.application_type is None:
            return False
        if snoopy_packet.transport_layer.transport_type.name in args.transport_include \
                and snoopy_packet.application_layer.application_type.name in args.application_include:
            return True

    return False


def handler(packet):
    raw_data = bytes(packet)
    if is_duplicate_packet(raw_data):
        return
    packets_set.add(raw_data)
    snoopy_packet = SnoopyPacket(raw_data=raw_data)

    if is_packet_of_interest(snoopy_packet):
        if args.verbose:
            snoopy_packet.print_packet_verbose()
            print("--------------------------------------------------------------------------------------------")
        else:
            snoopy_packet.print_packet_minimal()

        if args.save:
            pcapng_saver.save_packet(snoopy_packet)

    del snoopy_packet
    gc.collect()
    return


def main():
    interface_list = list(interface for index, interface in socket.if_nameindex())
    conf.bufsize = 6553600
    s = conf.L2listen(type=ETH_P_ALL,
                      filter="ip")
    sniff(opened_socket=s, prn=handler, store=0, iface=interface_list)


if __name__ == '__main__':
    packets_set = set()

    allowed_verbosity = [1, 2]
    allowed_network_type_name = list(i.name for i in NetworkType)
    allowed_transport_type_name = list(i.name for i in TransportType)
    allowed_application_type_name = list(i.name for i in ApplicationType)

    arg_parser = argparse.ArgumentParser(description="A packet sniffer in the works.",
                                         epilog="Developed by Gerald Lim Wee Koon (github: mathscantor)",
                                         formatter_class=argparse.RawTextHelpFormatter)

    # group = arg_parser.add_mutually_exclusive_group()
    arg_parser.add_argument('--save', dest='save', required=False, action='store_true',
                            help="Specify this argument to save sniffed packets into a pcapng file.")
    arg_parser.add_argument('--verbose', dest='verbose', required=False, action='store_true',
                            help="Specify this argument to save sniffed packets into a pcapng file.")
    arg_parser.add_argument('--network', dest='network_include', metavar="", nargs='+', type=str, required=False,
                            choices=allowed_network_type_name,
                            help="Supported Formats: {}".format(allowed_network_type_name))
    arg_parser.add_argument('--transport', dest='transport_include', metavar="", nargs='+', type=str, required=False,
                            choices=allowed_transport_type_name,
                            help="Supported Formats: {}".format(allowed_transport_type_name))
    arg_parser.add_argument('--application', dest='application_include', metavar="", nargs='+', type=str,
                            required=False,
                            choices=allowed_application_type_name,
                            help="Supported Formats: {}".format(allowed_application_type_name))

    arg_parser.set_defaults(save=False,
                            verbose=False)
    args = arg_parser.parse_args()

    has_network_filter = False
    has_transport_filter = False
    has_application_filter = False

    if args.network_include is not None:
        has_network_filter = True
    if args.transport_include is not None:
        has_transport_filter = True
    if args.application_include is not None:
        has_application_filter = True

    pcapng_saver = PcapngSaver()
    tcp_segments = {}  # To handle TCP reassembly
    main()
