import socket
from utils.packet import Packet
import gc
import argparse
from utils.pcapng_saver import PcapngSaver
from utils.layer_parsers.link import *
from utils.layer_parsers.network import *
from utils.layer_parsers.transport import *
from utils.layer_parsers.application import *


def is_duplicate_packet(raw_data: bytes) -> bool:
    is_duplicate = False
    if raw_data in packets_set:
        is_duplicate = True

    if len(packets_set) > 1000:
        packets_set.clear()

    return is_duplicate


def is_packet_of_interest(packet: Packet) -> bool:
    # No Filters specified, then return True
    if not has_network_filter and not has_transport_filter and not has_application_filter:
        return True

    # --network ...
    elif has_network_filter and not has_transport_filter and not has_application_filter:
        if packet.network_layer is None or packet.network_layer.network_type is None:
            return False
        if packet.network_layer.network_type.name in args.network_include:
            return True

    # --network ... --transport ...
    elif has_network_filter and has_transport_filter and not has_application_filter:
        if packet.network_layer is None or packet.network_layer.network_type is None:
            return False
        if packet.transport_layer is None or packet.transport_layer.transport_type is None:
            return False
        if packet.network_layer.network_type.name in args.network_include \
                and packet.transport_layer.transport_type.name in args.transport_include:
            return True

    # --network ... --application ...
    elif has_network_filter and not has_transport_filter and has_application_filter:
        if packet.network_layer is None or packet.network_layer.network_type is None:
            return False
        if packet.transport_layer is None or packet.transport_layer.transport_type is None:
            return False
        if packet.application_layer is None or packet.application_layer.application_type is None:
            return False
        if packet.network_layer.network_type.name in args.network_include \
                and packet.application_layer.application_type.name in args.application_include:
            return True

    elif has_network_filter and has_transport_filter and has_application_filter:
        if packet.network_layer is None or packet.network_layer.network_type is None:
            return False
        if packet.transport_layer is None or packet.transport_layer.transport_type is None:
            return False
        if packet.application_layer is None or packet.application_layer.application_type is None:
            return False
        if packet.network_layer.network_type.name in args.network_include \
                and packet.transport_layer.transport_type.name in args.transport_include \
                and packet.application_layer.application_type.name in args.application_include:
            return True

    # --transport ...
    elif not has_network_filter and has_transport_filter and not has_application_filter:
        if packet.transport_layer is None or packet.transport_layer.transport_type is None:
            return False
        if packet.transport_layer.transport_type.name in args.transport_include:
            return True

    # --application ...
    elif not has_network_filter and not has_transport_filter and has_application_filter:
        if packet.transport_layer is None or packet.transport_layer.transport_type is None:
            return False
        if packet.application_layer is None or packet.application_layer.application_type is None:
            return False
        if packet.application_layer.application_type.name in args.application_include:
            return True

    # --transport ... --application ...
    elif not has_network_filter and has_transport_filter and has_application_filter:
        if packet.transport_layer is None or packet.transport_layer.transport_type is None:
            return False
        if packet.application_layer is None or packet.application_layer.application_type is None:
            return False
        if packet.transport_layer.transport_type.name in args.transport_include \
                and packet.application_layer.application_type.name in args.application_include:
            return True

    return False


def handle_tcp_reassembly(packet: Packet) -> Packet:
    if packet.network_layer is None or packet.transport_layer is None:
        return
    if packet.transport_layer.transport_type is None:
        return

    if packet.transport_layer.transport_type != TransportType.TCP:
        return
    if packet.transport_layer.flag_syn == 1:
        tcp_segments[(packet.network_layer.src_ip,
                      packet.network_layer.dest_ip,
                      packet.transport_layer.src_port,
                      packet.transport_layer.dest_port)] = {}
    if len(packet.application_layer.application_data) > 0:
        tcp_segments[(packet.network_layer.src_ip,
                      packet.network_layer.dest_ip,
                      packet.transport_layer.src_port,
                      packet.transport_layer.dest_port)][
            packet.transport_layer.sequence] = packet.application_layer.application_data

    return


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65565)
        if is_duplicate_packet(raw_data):
            continue
        packets_set.add(raw_data)

        packet = Packet(raw_data=raw_data)
        if is_packet_of_interest(packet):
            packet.print_packet()
            print("--------------------------------------------------------------------------------------------")
            if args.save:
                pcapng_saver.save_packet(packet)

        del packet
        gc.collect()
    return


if __name__ == '__main__':
    packets_set = set()

    allowed_network_type_name = list(i.name for i in NetworkType)
    allowed_transport_type_name = list(i.name for i in TransportType)
    allowed_application_type_name = list(i.name for i in ApplicationType)

    arg_parser = argparse.ArgumentParser(description="A packet sniffer in the works.",
                                         epilog="Developed by Gerald Lim Wee Koon (github: mathscantor)",
                                         formatter_class=argparse.RawTextHelpFormatter)

    # group = arg_parser.add_mutually_exclusive_group()
    arg_parser.add_argument('--save', dest='save', required=False, action='store_true',
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

    arg_parser.set_defaults(save=False)
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
