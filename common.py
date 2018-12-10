import uuid

import rsa
from netfilterqueue import NetfilterQueue
from scapy.all import *

MAGIC = 0x42 # a magic identifying number

MSG_LEN = 16 # length of message
DATA_LEN = MSG_LEN + 64 # + length of signature

PUBKEY = rsa.PublicKey(10888551840171190772581446131615487397004739141476239826081159125184318457653121098130618388522625264228398784712748098397877149360163979789180129228494641, 65537)

def safety_check():
    # A list of MAC addresses on which this is allowed to run
    TEAM16_VMS_MAC = [0x52540044043d,
                      0x52540044043e,
                      0x52540044043f,
                      0x525400440440,
                      0x52540144043d,
                      0x52540144043e]
    # check if running on Team 16 VMs
    if uuid.getnode() not in TEAM16_VMS_MAC:
        print("Don't be evil!")
        exit(1)

def add_message(pkt, message):
    pkt = pkt/Raw(load=message)
    pkt.len += DATA_LEN
    return pkt

def get_message(pkt):
    data = bytes(pkt[TCP].payload)[-DATA_LEN:]

    # remove bot data
    pkt[TCP].payload = Raw(bytes(pkt[TCP].payload)[:-DATA_LEN])
    pkt.len -= DATA_LEN

    # verify signature
    if verify_message(data):
        print('got a new command!', data[1:MSG_LEN].decode('ascii'))
        return data
    else:
        print('verification failed!')
        return False

def verify_message(data):
    msg = data[:MSG_LEN]
    sig = data[MSG_LEN:]
    try:
        return rsa.verify(msg, sig, PUBKEY)
    except:
        return False
    return False

def set_and_accept(packet_in, pkt):
    # force a checksum recalc
    del pkt.chksum
    del pkt[TCP].chksum

    packet_in.set_payload(bytes(pkt))
    packet_in.accept()

def setup_queues(cb_input, cb_output):
    def route_packet(packet_in):
        if packet_in.get_mark() == 0x42:
            cb_input(packet_in)
        else:
            cb_output(packet_in)

    nfqueue = NetfilterQueue()
    nfqueue.bind(0, route_packet)
    try:
        print("[*] waiting for data")
        nfqueue.run()
    except KeyboardInterrupt:
        print('Got ^C, cleaning up')
    finally:
        nfqueue.unbind()
