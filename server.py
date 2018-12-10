#!/usr/bin/env python3

from scapy.all import *
from common import *

# in a real implementation these would expire at some point
happy_hosts = {}
last_message = bytes(DATA_LEN)

def callback_input(packet_in):
    global last_message
    pkt = IP(packet_in.get_payload())
    if TCP in pkt:
        # print(pkt[TCP].summary(), pkt.id)
        if pkt[TCP].flags.S and pkt.id == MAGIC: # Syn with MAGIC set
            print('Got a magic SYN!')
            happy_hosts[pkt.src] = pkt.seq + 1

        elif pkt[TCP].flags.A and pkt.id == MAGIC and happy_hosts.get(pkt.src) == pkt[TCP].ack: # matching ACK
            msg = get_message(pkt)
            if msg and msg[0] > last_message[0]:
                last_message = msg
            print('Got a happy ACK', msg)

    set_and_accept(packet_in, pkt)

def callback_output(packet_in):
    global last_message
    pkt = IP(packet_in.get_payload())
    # pkt.hide_defaults()
    # print(pkt[TCP].summary())
    if pkt.dst in happy_hosts and TCP in pkt:
        if pkt[TCP].flags.S and pkt[TCP].flags.A and happy_hosts.get(pkt.dst) == pkt.ack: # matching Syn/Ack
            print('Sending a magic SYN/ACK')
            pkt.id = MAGIC
            pkt = add_message(pkt, last_message)
            happy_hosts[pkt.dst] = pkt[TCP].seq + 1

    set_and_accept(packet_in, pkt)

safety_check()
setup_queues(callback_input, callback_output)
