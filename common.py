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
    nfqueue_input = NetfilterQueue()
    nfqueue_input.bind(0, cb_input)
    nfqueue_output = NetfilterQueue()
    nfqueue_output.bind(1, cb_output)
    try:
        print("[*] waiting for data")
        # TODO: better handling of ^C
        thread_input = Thread(target=nfqueue_input.run, daemon=True)
        thread_input.start()
        nfqueue_output.run()
    except KeyboardInterrupt:
        pass

    nfqueue_input.unbind()
    nfqueue_output.unbind()
