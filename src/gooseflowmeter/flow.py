from enum import Enum
from typing import Any

from . import constants
from .features.context import packet_flow_key
from .features.context.packet_direction import PacketDirection
from .features.flow_bytes import FlowBytes
from .features.packet_count import PacketCount
from .features.packet_length import PacketLength
from .features.packet_time import PacketTime
from .utils import get_statistics

from .features.goose.goose_data import get_goose_data_pdu
from .features.goose.goose_data import get_goose_sqNum
from .features.goose.goose_data import calculate_sqNum_norm
from .features.goose.goose_data import get_goose_reserved

class Flow:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, packet: Any, direction: Enum):
        """This method initializes an object from the Flow class.

        Args:
            packet (Any): A packet from the network.
            direction (Enum): The direction the packet is going ove the wire.
        """

        (            
            self.src_mac,
            self.dest_mac,
            self.appid,
            self.gocbRef,
            self.stNum
        ) = packet_flow_key.get_packet_flow_key(packet, direction)

        (
            self.timeAllowedtoLive,
            self.datSet,
            self.goID,
            self.test,
            self.confRev,
            self.ndsCom,
            self.numDatSetEntries
        ) = get_goose_data_pdu(packet)

        self.packets = []
        self.flow_interarrival_time = []
        self.latest_timestamp = 0
        self.start_timestamp = 0
        self.init_window_size = {
            PacketDirection.FORWARD: 0,
            PacketDirection.REVERSE: 0,
        }

        self.sqNum = []

        #self.reserved = 0
        self.reserved = int(get_goose_reserved(packet))

        self.start_active = 0
        self.last_active = 0
        self.active = []
        self.idle = []

        self.forward_bulk_last_timestamp = 0
        self.forward_bulk_start_tmp = 0
        self.forward_bulk_count = 0
        self.forward_bulk_count_tmp = 0
        self.forward_bulk_duration = 0
        self.forward_bulk_packet_count = 0
        self.forward_bulk_size = 0
        self.forward_bulk_size_tmp = 0

    def get_data(self) -> dict:
        """This method obtains the values of the features extracted from each flow.

        Note:
            Only some of the network data plays well together in this list.
            Time-to-live values, window values, and flags cause the data to
            separate out too much.

        Returns:
           list: returns a List of values to be outputted into a csv file.

        """

        flow_bytes = FlowBytes(self)
        packet_count = PacketCount(self)
        packet_length = PacketLength(self)
        packet_time = PacketTime(self)
        flow_iat = get_statistics(self.flow_interarrival_time)
        forward_iat = get_statistics(
            packet_time.get_packet_iat(PacketDirection.FORWARD)
        )

        active_stat = get_statistics(self.active)
        idle_stat = get_statistics(self.idle)

        data = {
            # Basic Ethernet information
            "src_mac": self.src_mac,
            "dst_mac": self.dest_mac,
            "appid": self.appid,
            "gocbRef": self.gocbRef,
            "stNum": self.stNum,# sqNum
            "sqNum_Norm": calculate_sqNum_norm(self.sqNum),
            # Other goose pdu parameters
            "timeAllowedtoLive": self.timeAllowedtoLive,
            "datSet": self.datSet,
            "goID": self.goID,
            "test": self.test,
            "confRev": self.confRev,
            "ndsCom": self.ndsCom,
            "numDatSetEntries": self.numDatSetEntries,
            # Basic information from packet times
            "timestamp": packet_time.get_time_stamp(),
            "flow_duration": 1e6 * packet_time.get_duration(),
            "flow_byts_s": flow_bytes.get_rate(),
            "flow_pkts_s": packet_count.get_rate(),
            # Count total packets by direction
            "tot_flow_pkts": packet_count.get_total(),            
            # Statistical info obtained from Packet lengths
            "tot_len_flow_pkts": packet_length.get_total(PacketDirection.FORWARD),
            "pkt_len_max": packet_length.get_max(),
            "pkt_len_min": packet_length.get_min(),
            "pkt_len_mean": float(packet_length.get_mean()),
            "pkt_len_std": float(packet_length.get_std()),
            "pkt_len_var": float(packet_length.get_var()),
            "pkt_len_median": float(packet_length.get_median()),
            # Statistical infor flow packet lengths
            "flow_header_len": flow_bytes.get_forward_header_bytes(),
            "flow_seg_size_min": flow_bytes.get_min_forward_header_bytes(),
            #"flow_act_data_pkts": packet_count.has_payload(PacketDirection.FORWARD),
            # Flows Interarrival Time
            "flow_iat_max": float(flow_iat["max"]),
            "flow_iat_min": float(flow_iat["min"]),
            "flow_iat_mean": float(flow_iat["mean"]),
            "flow_iat_std": float(flow_iat["std"]),
            "flow_iat_median": float(flow_iat["median"]),
            "flow_iat_tot": forward_iat["total"],
            # Response Time
            "pkt_size_avg": packet_length.get_avg(),
            "active_max": float(active_stat["max"]),
            "active_min": float(active_stat["min"]),
            "active_mean": float(active_stat["mean"]),
            "active_std": float(active_stat["std"]),
            "idle_max": float(idle_stat["max"]),
            "idle_min": float(idle_stat["min"]),
            "idle_mean": float(idle_stat["mean"]),
            "idle_std": float(idle_stat["std"]),
            "flow_byts_b_avg": float(flow_bytes.get_bytes_per_bulk(PacketDirection.FORWARD)),
            "flow_pkts_b_avg": float(flow_bytes.get_packets_per_bulk(PacketDirection.FORWARD)),            
            "flow_blk_rate_avg": float(flow_bytes.get_bulk_rate(PacketDirection.FORWARD)),
            "flow_label": self.reserved,
        }

        return data

    def add_packet(self, packet: Any, direction: Enum) -> None:
        """Adds a packet to the current list of packets.

        Args:
            packet: Packet to be added to a flow
            direction: The direction the packet is going in that flow

        """
        self.packets.append((packet, direction))

        self.update_flow_bulk(packet, direction)
        self.update_subflow(packet)

        if self.start_timestamp != 0:
            self.flow_interarrival_time.append(
                1e6 * (packet.time - self.latest_timestamp)
            )

        self.latest_timestamp = max([packet.time, self.latest_timestamp])

        # First packet of the flow
        if self.start_timestamp == 0:
            self.start_timestamp = packet.time

        # Collect sqNum
        self.sqNum.append(get_goose_sqNum(packet))

        # Reserved 1 for traffic labels
        #self.reserved = int(get_goose_reserved(packet))

    def update_subflow(self, packet):
        """Update subflow

        Args:
            packet: Packet to be parse as subflow

        """
        last_timestamp = (
            self.latest_timestamp if self.latest_timestamp != 0 else packet.time
        )
        if (packet.time - last_timestamp) > constants.CLUMP_TIMEOUT:
            self.update_active_idle(packet.time - last_timestamp)

    def update_active_idle(self, current_time):
        """Adds a packet to the current list of packets.

        Args:
            packet: Packet to be update active time

        """
        if (current_time - self.last_active) > constants.ACTIVE_TIMEOUT:
            duration = abs(float(self.last_active - self.start_active))
            if duration > 0:
                self.active.append(1e6 * duration)
            self.idle.append(1e6 * (current_time - self.last_active))
            self.start_active = current_time
            self.last_active = current_time
        else:
            self.last_active = current_time

    def update_flow_bulk(self, packet, direction):
        """Update bulk flow

        Args:
            packet: Packet to be parse as bulk

        """
        payload_size = PacketCount.get_payload(packet) # len of int 
        if payload_size == 0:
            return
        if direction == PacketDirection.FORWARD:
            if self.forward_bulk_start_tmp == 0:
                self.forward_bulk_start_tmp = packet.time
                self.forward_bulk_last_timestamp = packet.time
                self.forward_bulk_count_tmp = 1
                self.forward_bulk_size_tmp = payload_size
            else:
                if (
                    packet.time - self.forward_bulk_last_timestamp
                ) > constants.CLUMP_TIMEOUT:
                    self.forward_bulk_start_tmp = packet.time
                    self.forward_bulk_last_timestamp = packet.time
                    self.forward_bulk_count_tmp = 1
                    self.forward_bulk_size_tmp = payload_size
                else:  # Add to bulk
                    self.forward_bulk_count_tmp += 1
                    self.forward_bulk_size_tmp += payload_size
                    if self.forward_bulk_count_tmp == constants.BULK_BOUND:
                        self.forward_bulk_count += 1
                        self.forward_bulk_packet_count += self.forward_bulk_count_tmp
                        self.forward_bulk_size += self.forward_bulk_size_tmp
                        self.forward_bulk_duration += (
                            packet.time - self.forward_bulk_start_tmp
                        )
                    elif self.forward_bulk_count_tmp > constants.BULK_BOUND:
                        self.forward_bulk_packet_count += 1
                        self.forward_bulk_size += payload_size
                        self.forward_bulk_duration += (
                            packet.time - self.forward_bulk_last_timestamp
                        )
                    self.forward_bulk_last_timestamp = packet.time

    @property
    def duration(self):
        return self.latest_timestamp - self.start_timestamp
