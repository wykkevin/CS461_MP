from scapy.all import *

import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])
    
    # SYN scan
    ip = IP(dst=ip_addr)

    for i in range(1, 1025, 100):
        ports = (i, min(i+100-1, 1024))
        tcp = TCP(dport=ports, flags="S")
        layers = ip/tcp
        ans, unans = sr(layers, timeout=0.25, verbose=0)
    
        half_open_ports = []
        for req, resp in ans:

            if resp and resp.haslayer(TCP):
                # If TCP port open, record
                if resp[TCP].flags == 0x12:  # SYN & ACK
                    print(f"{ip_addr},{resp[TCP].sport}")
                    # and send RST
                    half_open_ports.append(resp[TCP].sport)
        
        # Close half open connections
        sr(ip/TCP(dport=half_open_ports, flags='AR'), timeout=1, verbose=0)
    

