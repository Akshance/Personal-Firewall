#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

BLOCKED_IPS = {'203.0.113.5'}
BLOCKED_TCP_PORTS = {23, 445}
LOG = True

def drop_packet(pkt):
    ip = IP(pkt.get_payload())
    src, dst = ip.src, ip.dst
    if src in BLOCKED_IPS or dst in BLOCKED_IPS:
        if LOG: print(f'DROP IP: {src} -> {dst}')
        return True
    if ip.haslayer(TCP):
        sport, dport = ip[TCP].sport, ip[TCP].dport
        if sport in BLOCKED_TCP_PORTS or dport in BLOCKED_TCP_PORTS:
            if LOG: print(f'DROP PORT: {src}:{sport} -> {dst}:{dport}')
            return True
    return False

def handler(pkt):
    try:
        if drop_packet(pkt):
            pkt.drop()
        else:
            pkt.accept()
    except Exception as e:
        print('Error:', e)
        pkt.accept()

def main():
    nf = NetfilterQueue()
    try:
        nf.bind(1, handler)
        print('Firewall running. Ctrl+C to stop.')
        nf.run()
    except KeyboardInterrupt:
        print('Stopping.')
    finally:
        nf.unbind()

if __name__ == '__main__':
    main()
