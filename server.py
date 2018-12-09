#!/usr/bin/env python3

from scapy.all import *
from common import *

# in a real implementation these would expire at some point
happy_hosts = {}

def callback_input(packet_in):
    pkt = IP(packet_in.get_payload())
    if TCP in pkt:
        print(pkt[TCP].summary(), pkt.id)
        if pkt[TCP].flags.S and pkt.id == MAGIC: # Syn with MAGIC set
            print('Got a magic SYN!')
            happy_hosts[pkt.src] = 0

        elif pkt[TCP].flags.A and pkt.id == MAGIC and happy_hosts[pkt.src] == pkt[TCP].ack: # matching ACK
            print('Got a happy ACK')

    set_and_accept(packet_in, pkt)

def callback_output(packet_in):
    pkt = IP(packet_in.get_payload())
    # pkt.hide_defaults()
    print(pkt[TCP].summary())
    print(happy_hosts)
    if pkt.dst in happy_hosts and TCP in pkt:
        if pkt[TCP].flags.S and pkt[TCP].flags.A and pkt.dst in happy_hosts: # matching Syn/Ack
            pkt.id = MAGIC
            print('sending a magic SYN/ACK')
            happy_hosts[pkt.dst] = pkt[TCP].seq + len(pkt[TCP].payload) + 1

    set_and_accept(packet_in, pkt)

safety_check()
setup_queues(callback_input, callback_output)
