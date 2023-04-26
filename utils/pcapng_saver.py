import os
from datetime import datetime
from utils.pcapng.writer import FileWriter
import utils.pcapng.blocks as blocks
from utils.snoopy_packet import SnoopyPacket


# Global Options
SHB_INTERFACE_OPTIONS = {"if_description": "Hand-rolled", "if_os": "Python"}
SHB_HEADER_OPTIONS = {"shb_hardware": "artificial", "shb_os": "python", "shb_userappl": "python-pcapng"}


class PcapngSaver:

    def __init__(self):
        self.__file_path = "capture/capture_{}.pcapng".format(datetime.now().strftime('%d-%m-%Y_%H:%M:%S'))
        os.makedirs(os.path.dirname(self.__file_path), exist_ok=True)

        self.__shb = blocks.SectionHeader(options=SHB_HEADER_OPTIONS)
        self.__shb.new_member(blocks.InterfaceDescription, link_type=1, options=SHB_INTERFACE_OPTIONS)

    def save_packet(self, packet: SnoopyPacket):
        with open(self.__file_path, 'ab') as file_obj:
            writer = FileWriter(file_obj, self.__shb)
            spb = self.__shb.new_member(blocks.SimplePacket)
            spb.packet_data = packet.raw_data
            writer.write_block(spb)


