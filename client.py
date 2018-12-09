#!/usr/bin/env python3

from scapy.all import *
from common import *

happy_hosts = {}

def callback_input(packet_in):
    pkt = IP(packet_in.get_payload())
    # pkt.hide_defaults()
    if TCP in pkt:
        print(pkt[TCP].summary(), pkt.id)
        if pkt[TCP].flags.S and pkt[TCP].flags.A and pkt.id == MAGIC: # Magic Syn/Ack
            print('Got a magic SYN/ACK')
            happy_hosts[pkt.src] = pkt[TCP].seq + len(pkt[TCP].payload) + 1

    set_and_accept(packet_in, pkt)

def callback_output(packet_in):
    pkt = IP(packet_in.get_payload())
    if TCP in pkt:
        print(pkt[TCP].summary())
        if pkt[TCP].flags.S: # we are sending a Syn
            print('Sending a magic SYN!')
            pkt.id = MAGIC

        elif pkt[TCP].flags.A and happy_hosts[pkt.dst] == pkt[TCP].ack: # matching ACK
            print('Sending a happy ACK')
            pkt.id = MAGIC

    set_and_accept(packet_in, pkt)

safety_check()
setup_queues(callback_input, callback_output)
