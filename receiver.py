from scapy.all import *
from goose import GOOSE
from goose_pdu import IECGoosePDU
from pyasn1.codec.ber import encoder
from pyasn1.type import tag
from BlockChain import Message, Block, SimpleChain
import json
import argparse
import time

parser = argparse.ArgumentParser()
parser.add_argument("--ip",required=True, type=str, default="127.0.0.2")
args = parser.parse_args()

chain = SimpleChain()
block = Block()

tasks = {'Registration': 1, 'Payload': 2, 'Verify': 3, 'VerificationDone': 4}
number_to_tasks = {v:k for k, v in tasks.items()}
signature = '00001'

listOfNodes = ['127.0.0.3', '127.0.0.1', '127.0.0.2']

verificationList = {}


def checkVerificationList(verificationList, maxNumNodes=5):
    if sum(verificationList) > maxNumNodes//2:
        return True
    return False

def send_packet(dst, data):
    print('Sent Packet Type:', number_to_tasks[data['task_type']], args.ip, dst)
    if(data['task_type'] == 4):
        time.sleep(2)
    data_string = json.dumps(data)
    #SENDING THE RGOOSE PACKET
    sendp(Ether(dst='01:0c:cd:01:00:14') /
                IP(src=args.ip, dst=dst) /
                UDP(sport=50000, dport=50001) /
                data_string, iface='en0')

while True:
    # IFACE_NAME = IFACES.dev_from_name("Realtek Gaming GbE Family Controller")
    packet_data = sniff(filter="udp and host " + args.ip, count=1, iface='en0')

    packet = packet_data[-1].lastlayer()
    s = packet["Raw"].load
    data = json.loads(s)

    if data["flag"]:
        continue


    # Verify
    if data["task_type"] == 3:
        device_id = data['device_id']
        public_key = chain.getPublicKey(device_id)
        # Verification        
        if(chain.verifySignature(public_key, data['signature'], data['payload'])):
            # Verfication OK
            # Send Verification true packet to src
            send_data = {'flag':False, 'device_name':'Device 1', 'task_type':4, 'device_id': 1, 'payload': data['payload'], 'signature': signature, 'verification': True, 'transaction_id': data['transaction_id']}
            send_packet(str(packet_data[-1]['IP'].src), send_data)

        else:
            # Send Verification false packet to src
            send_data = {'flag':False, 'device_name':'Device 1', 'task_type':4, 'device_id': 1, 'payload': data['payload'], 'signature': signature, 'verification': False, 'transaction_id': data['transaction_id']}
            send_packet(str(packet_data[-1]['IP'].src), send_data)

    
    # VerificationDone
    if data["task_type"] == 4:
        verificationList[data['transaction_id']].append(data['verification'])
        if checkVerificationList(verificationList[data['transaction_id']], maxNumNodes=3):
            # TODO: correct algo for verificationList
            verificationList[data['transaction_id']] = []
            print('Signature Verified')
            # Decrypt payload


    # Payload
    if data["task_type"] == 2:
        device_id = data['device_id']
        public_key = chain.getPublicKey(device_id)
        # Verification
        if(chain.verifySignature(public_key, data['signature'], data['payload'])):
            # Verfication OK
            # Send for verification

            verificationList[data['transaction_id']] = [True]

            send_data = {'flag':False, 'device_name':data['device_name'], 'task_type':3, 'device_id': data['device_id'], 'payload': data['payload'], 'signature': data['signature'], 'verfication': True, 'transaction_id': data['transaction_id']}
            for node in listOfNodes:
                if node not in [str(packet_data[-1]['IP'].src), str(packet_data[-1]['IP'].dst)]:
                    send_packet(node, send_data)
        else:
            print('Failed Verification')

    # Registration
    if data["task_type"] == 1:

        device_id = data['device_id']
        public_key = data['payload']

        if(not chain.verifyRegistered(device_id)):
            # Not Registered
            block.add_message(Message((device_id, public_key)))
            chain.add_block(block)
            block = Block()
            print('Sucessfully Registered')
            send_data = data
            for node in listOfNodes:
                if node not in [str(packet_data[-1]['IP'].src), str(packet_data[-1]['IP'].dst)]:
                    send_packet(node, send_data)

        else:
            print('Already Registered')

    if data["task_type"] not in [1, 2, 3, 4]:
        print('Malformed Packet')
        

    for b in chain.chain:
        print(b)
        print("----------------")
