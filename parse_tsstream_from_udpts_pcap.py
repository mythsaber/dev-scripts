#!/usr/bin/env python
# Read a .pcap file full of UDP packets, extract udp payload
# usage: python parse.py zcj.pcap zcj.ts
import dpkt
import sys
def parse(inName, outName):
    with open(inName,'rb') as fin:
        with  open(outName,'wb') as fout:
            pcap = dpkt.pcap.Reader(fin)
            for ts, buf in pcap:
                if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
                    l2pkt = dpkt.sll.SLL(buf)
                elif pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL2:
                    l2pkt = dpkt.sll2.SLL2(buf)
                else:
                    l2pkt = dpkt.ethernet.Ethernet(buf)
                ip = l2pkt.data
                udp = ip.data
                velodata = udp.data
                fout.write(velodata)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('ERROR: must supply pcap filename, output filename')
        sys.exit(1)
    parse(sys.argv[1],sys.argv[2])