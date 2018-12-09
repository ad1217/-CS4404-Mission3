import uuid

from netfilterqueue import NetfilterQueue
from scapy.all import *

MAGIC = 0x42 # a magic identifying number

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
