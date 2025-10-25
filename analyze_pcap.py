#!/usr/bin/env python3
# Requires scapy: pip3 install scapy
from scapy.all import rdpcap, TCP, Raw, IP
import re, base64, os, sys
from collections import defaultdict

PCAP = sys.argv[1] if len(sys.argv)>1 else "WebServer.pcap"
KEY = b"5eCuR3"
b64_pat = re.compile(rb'[A-Za-z0-9+/]{16,}={0,2}')

def printable(b):
    return ''.join(chr(x) if 32<=x<=126 else f"\\x{x:02x}" for x in b)

pkts = rdpcap(PCAP)
flows = defaultdict(list)
for p in pkts:
    if IP in p and TCP in p:
        ip=p[IP]; tcp=p[TCP]
        fid=(ip.src, ip.dst, tcp.sport, tcp.dport)
        payload = bytes(p[Raw].load) if Raw in p else b""
        flows[fid].append(payload)
# concatenate (simple)
for fid, parts in flows.items():
    data=b"".join(parts)
    auths = re.findall(rb'(?:auth|data)=[A-Za-z0-9%+=/.-]+', data)
    b64s=set(m.group(0) for m in b64_pat.finditer(data))
    if auths or b64s:
        print("FLOW:", fid, "size", len(data))
        if auths:
            print(" auth/data:", [a.decode(errors='ignore') for a in auths])
        for c in b64s:
            try:
                raw = base64.b64decode(c)
            except Exception:
                continue
            rev = raw[::-1]
            xored = bytes([rev[i] ^ KEY[i % len(KEY)] for i in range(len(rev))])
            print(" candidate:", c[:120].decode(errors='ignore'))
            print("  decoded:", printable(xored)[:400])
        print()
