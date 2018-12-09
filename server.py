#!/usr/bin/env python3

from threading import Thread
import uuid

from netfilterqueue import NetfilterQueue
from scapy.all import *

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

MAGIC = 0x42 # a magic identifying number

# in a real implementation these would expire at some point
happy_hosts = {}

def callback_input(packet):
    pkt = IP(packet.get_payload())
    if TCP in pkt:
        print(pkt[TCP].summary(), pkt.id)
        if pkt[TCP].flags.S and pkt.id == MAGIC: # Syn with MAGIC set
            print('Got a magic SYN!')
            happy_hosts[pkt.src] = 0

        elif pkt[TCP].flags.A and pkt.id == MAGIC and happy_hosts[pkt.src] == pkt[TCP].ack: # matching ACK
            print('Got a happy ACK')

    # force a checksum recalc
    del pkt.chksum
    del pkt[TCP].chksum

    packet.set_payload(bytes(pkt))
    packet.accept()

def callback_output(packet):
    pkt = IP(packet.get_payload())
    # pkt.hide_defaults()
    print(pkt[TCP].summary())
    print(happy_hosts)
    if pkt.dst in happy_hosts and TCP in pkt:
        if pkt[TCP].flags.S and pkt[TCP].flags.A and pkt.dst in happy_hosts: # matching Syn/Ack
            pkt.id = MAGIC
            print('sending a magic SYN/ACK')
            happy_hosts[pkt.dst] = pkt[TCP].seq + len(pkt[TCP].payload) + 1

    # force a checksum recalc
    del pkt.chksum
    del pkt[TCP].chksum

    packet.set_payload(bytes(pkt))
    packet.accept()

nfqueue_input = NetfilterQueue()
nfqueue_input.bind(0, callback_input)
nfqueue_output = NetfilterQueue()
nfqueue_output.bind(1, callback_output)
try:
    print("[*] waiting for data")
    thread_input = Thread(target=nfqueue_input.run, daemon=True)
    thread_input.start()
    nfqueue_output.run()
except KeyboardInterrupt:
    pass

nfqueue_input.unbind()
nfqueue_output.unbind()
