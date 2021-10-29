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
import argparse
import time 

parser = argparse.ArgumentParser()
parser.add_argument("--src_ip",required=False, type=str, default="127.0.0.1")
parser.add_argument("--dst_ip",required=False, type=str, default="127.0.0.2")
args = parser.parse_args()


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
hexdump(
    Ether(dst='01:0c:cd:01:00:14') /
    Dot1Q(vlan=10, type=0x88b8, prio=6) /
    GOOSE(appid=int(0x00b1)) /
    encoder.encode(g)
)

#SETTING THE INTERFACE
# IFACE_NAME = IFACES.dev_from_name("Realtek Gaming GbE Family Controller")

#SENDING THE GOOSE PACKET
# sendp(Ether(dst='01:0c:cd:01:00:14') /
#             Dot1Q(vlan=10, type=0x88b8, prio=6) /
#             GOOSE(appid=int(0x00b1)) /
#             encoder.encode(g), iface='en0')


tasks = {'Registration': 1, 'Payload': 2, 'Verify': 3, 'VerificationDone': 4}
number_to_tasks = {v:k for k, v in tasks.items()}

signature = '00000'

data = {'flag':False, 'device_name':'Device 0', 'task_type':1, 'device_id': 0, 'payload': args.src_ip, 'signature': signature, 'verfication': False, 'transaction_id': 0}

data_string = json.dumps(data)
#SENDING THE RGOOSE PACKET
sendp(Ether(dst='01:0c:cd:01:00:14') /
            IP(src=args.src_ip, dst=args.dst_ip) /
            UDP(sport=50000, dport=50001) /
            data_string, iface='en0')

time.sleep(2)

data = {'flag':False, 'device_name':'Device 0', 'task_type':2, 'device_id': 0, 'payload': str(encoder.encode(g)), 'signature': signature, 'verfication': False, 'transaction_id': 0}

data_string = json.dumps(data)
#SENDING THE RGOOSE PACKET
sendp(Ether(dst='01:0c:cd:01:00:14') /
            IP(src=args.src_ip, dst=args.dst_ip) /
            UDP(sport=50000, dport=50001) /
            data_string, iface='en0')
