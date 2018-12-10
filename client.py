#!/usr/bin/env python3

import os

from scapy.all import *
from common import *

last_message = bytes(DATA_LEN)
happy_hosts = {}

def callback_input(packet_in):
    global last_message
    pkt = IP(packet_in.get_payload())
    # pkt.hide_defaults()
    if TCP in pkt:
        # print(pkt[TCP].summary(), pkt.id)
        if pkt[TCP].flags.S and pkt[TCP].flags.A and pkt.id == MAGIC: # Magic Syn/Ack
            msg = get_message(pkt)
            if msg and msg[0] > last_message[0]:
                last_message = msg
            print('Got a magic SYN/ACK:', msg)
            happy_hosts[pkt.src] = pkt[TCP].seq + 1

    set_and_accept(packet_in, pkt)

def callback_output(packet_in):
    global last_message
    pkt = IP(packet_in.get_payload())
    if TCP in pkt:
        # print(pkt[TCP].summary())
        if pkt[TCP].flags.S: # we are sending a Syn
            print('Sending a magic SYN!')
            pkt.id = MAGIC

        elif pkt[TCP].flags.A and happy_hosts.get(pkt.dst) == pkt[TCP].ack: # matching ACK
            print('Sending a happy ACK')
            pkt.id = MAGIC
            pkt = add_message(pkt, last_message)

    set_and_accept(packet_in, pkt)

if os.path.isfile('./lastmsg.bin'):
    with open('./lastmsg.bin', 'rb') as f:
        msg = f.read()
        if verify_message(msg):
            last_message = msg

safety_check()
setup_queues(callback_input, callback_output)
