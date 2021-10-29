#IMPORTS
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.l2 import Dot1Q
from scapy.utils import hexdump
from goose import GOOSE
from goose_pdu import IECGoosePDU
from pyasn1.codec.ber import encoder
from pyasn1.type import tag
import json


#DEFINING GOOSE PACKET
g = IECGoosePDU().subtype(
    implicitTag=tag.Tag(
        tag.tagClassApplication,
        tag.tagFormatConstructed,
        1
     )
)

#SETTING ATTRIBUTE VALUES IN GOOSE PACKET
g.setComponentByName('gocbRef', 'PDC-2+11+700G_G1CFG/LLNO$GO$GooseDset_BF')
g.setComponentByName('timeAllowedtoLive', 2000)
g.setComponentByName('datSet', 'PDC02_11_700G_G1CFG/LLN0$Dset_BF')
g.setComponentByName('goID', '11_700G_G1_Dset_BF')
g.setComponentByName('t', b'\x55\x15\x1b\x9b\x69\x37\x40\x92')
g.setComponentByName('stNum', 5)
g.setComponentByName('sqNum', 1757)
g.setComponentByName('test', False)
g.setComponentByName('confRev', 3)
g.setComponentByName('ndsCom', False)
g.setComponentByName('numDatSetEntries', 6)


# HEXDUMP OF THE GOOSE PACKET
# hexdump(
#     Ether(dst='01:0c:cd:01:00:14') /
#     Dot1Q(vlan=10, type=0x88b8, prio=6) /
#     GOOSE(appid=int(0x00b1)) /
#     encoder.encode(g)
# )

#SETTING THE INTERFACE
IFACE_NAME = IFACES.dev_from_name("Realtek Gaming GbE Family Controller")

#SENDING THE GOOSE PACKET
sendp(Ether(dst='01:00:5e:00:00:00') /
            Dot1Q(vlan=10, type=0x88b8, prio=6) /
            GOOSE(appid=int(0x00b1)) /
            encoder.encode(g), iface=IFACE_NAME)

#SENDING THE RGOOSE PACKET
# sendp(Ether(dst='01:0c:cd:01:00:14') /
#             IP(dst="127.124.124.232", ihl=5) /
#             UDP(sport=50000, dport=50001) /
#             GOOSE(appid=int(0x00b1)) /
#             encoder.encode(g), iface=IFACE_NAME)

data = {'msg':True,'name':'Device 1','task':1}
data_string = json.dumps(data)

class MyUDP(UDP):
    fields_desc = UDP.fields_desc.copy()
    fields_desc.append(StrLenField("signature","12345",10))

# data = b'\x01@\xa1\x17\x80\x15\x00\x00\x00\xaf\x00\x00\x00\x0f\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x9a\x81\x00\x00\x05\x00\x94a\x81\x91\x800RGOOSE_CCCONTROL_CENTER_PS/LLN0$RG$CC_RGOOSE_GCB\x81\x02\x0f\xa0\x821RGOOSE_CCCONTROL_CENTER_PS/LLN0$CC_RGOOSE_dataset\x83\x05rtds1\x84\x08A\xcd\xd5"\xeb\x8b\xbb\x1f\x85\x01e\x86\x01\x0e\x87\x01\x00\x88\x01\x01\x89\x01\x00\x8a\x01\x01\xab\x03\x83\x01\x00'

data = b'\x01@\xa1\x17\x80\x15\x00\x00\x00\xaf\x00\x00\x00\x0f\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x01\x01\x00\x00\x9a\x81\x00\x00\x05\x00\x94a\x81\x91\x800RGOOSE_CCCONTROL_CENTER_PS/LLN0$RG$CC_RGOOSE_GCB\x81\x02\x0f\xa0\x821RGOOSE_CCCONTROL_CENTER_PS/LLN0$CC_RGOOSE_dataset\x83\x05rtds1\x84\x08A\xcd\xd5"\xeb\x8b\xbb\x1f\x85\x01e\x86\x01\x0e\x87\x01\x00\x88\x01\x01\x89\x01\x00\x8a\x01\x01\xab\x03\x83\x01\x00'
data = b'\x01@\xa1\x17\x80\x15\x00\x00\x00\xaf\x00\x00\x00\x0f\x00\x02\x00\x00\x00\x00\x00\x00\x01\x00\x01\x01\x01\x01\x00\x00\x9a\x81\x00\x00\x05\x00\x94a\x81\x91\x800RGOOSE_CCCONTROL_CENTER_PS/LLN0$RG$CC_RGOOSE_GCB\x81\x02\x0f\xa0\x821RGOOSE_CCCONTROL_CENTER_PS/LLN0$CC_RGOOSE_dataset\x83\x05rtds1\x84\x08A\xcd\xd5"\xeb\x8b\xbb\x1f\x85\x01e\x86\x01\x0e\x87\x01\x00\x88\x01\x01\x89\x01\x00\x8a\x01\x01\xab\x03\x83\x01\x00'

#SENDING THE RGOOSE PACKET
sendp(Ether(dst='01:00:5e:7f:ff:ff', src='00:50:c2:4f:9d:cd') / IP(src='10.220.64.206', dst="239.255.255.255", ihl=5) / UDP(sport=49157, dport=102) / data, iface=IFACE_NAME)

# sendp(Ether(dst='01:00:5e:7f:ff:ff', src='00:50:c2:4f:9d:cd') / IP(src='10.220.64.206', dst="239.255.255.255", ihl=5, len=213, id=15, chksum = b"0x3e60") / UDP(sport=49157, dport=102, len=193, chksum = b"0x791") / Raw(load=data), iface=IFACE_NAME)
