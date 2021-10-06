from scapy.all import *
from goose import GOOSE
from goose_pdu import IECGoosePDU
from pyasn1.codec.ber import encoder
from pyasn1.type import tag
from BlockChain import Message, Block, SimpleChain
import json

chain = SimpleChain()
block = Block()

while True:
    IFACE_NAME = IFACES.dev_from_name("Realtek Gaming GbE Family Controller")
    data = sniff(filter="udp and host 127.0.0.2", count=1, iface=IFACE_NAME)

    packet = data[-1].lastlayer()
    s = packet["Raw"].load
    d = json.loads(s)

    if d["task"] == 1:
        block.add_message(Message(d["name"]))
        chain.add_block(block)
        block = Block()
        
    for b in chain.chain:
        print(b)
        print("----------------")
