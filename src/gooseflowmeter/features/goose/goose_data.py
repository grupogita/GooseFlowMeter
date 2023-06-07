import datetime

from scapy.all import Dot1Q, Ether
from pyasn1.codec.ber import decoder
from pyasn1.type import char
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1 import debug

from .goose import GOOSE
from .goose import GOOSEPDU
from .goose_pdu import AllData
from .goose_pdu import Data
from .goose_pdu import IECGoosePDU
from .goose_pdu import UtcTime

def get_gooseASN1_PDU(data):
    dict_pdu = {}
    for e in list(IECGoosePDU()):
        if not data[e].hasValue():
            continue
        if type(data[e]) == char.VisibleString:
            dict_pdu[e] = str(data[e])
            continue
        if type(data[e]) == univ.Integer:
            dict_pdu[e] = int(data[e])
            continue
        if type(data[e]) == UtcTime:
            dict_pdu[e] = datetime.datetime.fromtimestamp(int.from_bytes(bytearray(data[e])[:4],'big')).strftime('%Y-%m-%d %H:%M:%S')
            continue
        if type(data[e]) == univ.Boolean:
            dict_pdu[e] = str(data[e])
            continue
        if type(data[e]) == AllData:
            list_data = []
            for e in data.getComponentByName('allData'):
                for k, v in e.items():
                    list_data.append((str(k), str(v)))
            dict_pdu["allData"] = list_data
            continue
        if type(data[e]) == univ.OctetString:
            continue
    return dict_pdu
    

def get_gooseASN1_PDU_vendorA(gd):
    print('\n\n')
    dict_pdu = {}
    for e in list(IECGoosePDU()):
        if not gd[e].hasValue():
            continue
        if type(gd[e]) == char.VisibleString:
            print('%s: %s'%(e,str(gd[e])))
            dict_pdu[e] = (e,str(gd[e]))
            continue
        if type(gd[e]) == univ.Integer:
            print('%s: %s'%(e,int(gd[e])))
            dict_pdu[e] = (e,int(gd[e]))
            continue
        if type(gd[e]) == UtcTime:
            print('%s: %s'%(e,datetime.datetime.fromtimestamp(int.from_bytes(bytearray(gd[e])[:4],'big')).strftime('%Y-%m-%d %H:%M:%S')))
            dict_pdu[e] = (e,datetime.datetime.fromtimestamp(int.from_bytes(bytearray(gd[e])[:4],'big')).strftime('%Y-%m-%d %H:%M:%S'))
            continue
        if type(gd[e]) == univ.Boolean:
            print('%s: %s'%(e,str(gd[e])))
            dict_pdu[e] = (e,str(gd[e]))
            continue
        if type(gd[e]) == AllData:
            print('%s'%(e))
            tmpstr = []
            for e in gd.getComponentByName('allData'):
                for v in e.values():
                    tmpstr.append(str(v))
            # Some vendors send two values for each value. Value1) the actual value Value2) quality 
            # Join these into colon seperated values for readability
            for e in [': '.join(x) for x in zip(tmpstr[0::2],tmpstr[1::2])]:
                print('%s%s'%('    ',e))
            continue
        if type(gd[e]) == univ.OctetString:
            print('%s: %s'%(e,str(gd[e])))
            continue
    print(dict_pdu)


def goose_pdu_decode(encoded_data):
    #debug.setLogger(debug.Debug('all'))
    g = IECGoosePDU().subtype(
        implicitTag=tag.Tag(
            tag.tagClassApplication,
            tag.tagFormatConstructed,
            1
        )
    )
    try:
        decoded_data, _ = decoder.decode(
            encoded_data,
            asn1Spec=g
        )
        return decoded_data
    except Exception:
        print("GOOSE malformed")
        return None

def get_goose_data(packet):

    p = packet.payload
    d = GOOSE(p.load)

    # Grab the Goose PDU for processing
    gpdu = d[GOOSEPDU].original
    
    # Use PYASN1 to parse the Goose PDU
    gd = goose_pdu_decode(gpdu)
    if gd is not None:
        data = get_gooseASN1_PDU(gd)
        #data = get_gooseASN1_PDU_vendorA(gd)
        return data
    else:
        return None

def get_appid(packet):
    p = packet.payload
    d = GOOSE(p.load)
    return d.appid        

def get_payload_length(packet):
    p = packet.payload
    d = GOOSE(p.load)
    return d.length

def get_reserved(packet):
    p = packet.payload
    d = GOOSE(p.load)
    reserved = [d.reserved1, d.reserved2]
    return reserved

def get_goose_data_pdu(packet):

    timeAllowedtoLive = 0
    datSet = 0
    goID = 0 
    test = 0
    confRev = 0
    ndsCom = 0
    numDatSetEntries = 0

    pdu_data = get_goose_data(packet)

    if pdu_data is not None:
        timeAllowedtoLive = pdu_data['timeAllowedtoLive']
        datSet = pdu_data['datSet']
        goID = pdu_data['goID']
        test = pdu_data['test']
        confRev = pdu_data['confRev']
        ndsCom = pdu_data['ndsCom']
        numDatSetEntries = pdu_data['numDatSetEntries']

    return timeAllowedtoLive,datSet, goID, test, confRev, ndsCom, numDatSetEntries

def get_goose_sqNum(packet):
    pdu_data = get_goose_data(packet)
    if pdu_data is not None:
        return pdu_data['sqNum']
    else:
        return 0

def calculate_sqNum_norm(sqnum):
    if len(sqnum) != 1:
        norm = (max(sqnum)-min(sqnum) + 1)/len(sqnum)
        return norm
    else: 
        return 1
    
def get_goose_reserved(packet):
    p = packet.payload
    d = GOOSE(p.load)
    reserved = d.reserved1
    return reserved