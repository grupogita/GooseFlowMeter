#!/usr/bin/env python

from .packet_direction import PacketDirection
from ..goose.goose_data import get_appid
from ..goose.goose_data import get_goose_data


def get_packet_flow_key(packet, direction) -> tuple:
    """Creates a key signature for a packet.

    Summary:
        Creates a key signature for a packet so it can be
        assigned to a flow.

    Args:
        packet: A network packet
        direction: The direction of a packet

    Returns:
        A tuple with flow keys: src mac, dst mac, appid, gocbRef, stNum
    """

    src_mac = '0.0.0.0.'
    dest_mac = '0.0.0.0.'
    appid = 0
    gocbRef = 'ErrorStructureDataSetPDU'
    stNum = 0
    
    if "TCP" in packet:
        return
    elif "UDP" in packet:
        return
    
    appid = get_appid(packet)
    pdu_data = get_goose_data(packet)

    if pdu_data is not None:

        gocbRef = pdu_data['gocbRef']
        stNum = pdu_data['stNum']
        
    if direction == PacketDirection.FORWARD:
        dest_mac = packet["Ether"].dst
        src_mac = packet["Ether"].src
    else:
        dest_mac = packet["Ether"].src
        src_mac = packet["Ether"].dst
        
    return src_mac, dest_mac, appid, gocbRef, stNum