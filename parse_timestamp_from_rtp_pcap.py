# encoding:utf-8
import dpkt
import sys
import os
import struct
import csv
from bitstring import BitString
import datetime
from optparse import OptionParser
"""
功能：
    该脚本适用于udp rtp pcap文件
    从pcap中解析抓包时刻点、ts流时间戳
"""

"""
Usage:
  -i            input udp_rtp pcap file
  -v            verbose mode, print rtp header info  (default false)
  -e            if set then exit once the first error detected  (default false)
"""


def parse_options():
    parser = OptionParser(
        usage="%prog [-i]  [-v]  [-e]  [-s]", version="%prog 1.0")

    parser.add_option("-i",
                      dest="filename",
                      help="input udp rtp pcap file",
                      type="string",
                      action="store"
                      )

    parser.add_option("-v",
                      dest="verbose",
                      help="verbose mode  (default false)",
                      action="store_true",
                      default=False)

    parser.add_option("-e",
                      dest="exitonerror",
                      help="if set then exit once the first error detected  (default false)",
                      action="store_true",
                      default=False)

    parser.add_option("-s",
                      dest="savepayload",
                      help="save rtp payload",
                      action="store_true",
                      default=False)                 

    (options, args) = parser.parse_args()

    if options.filename:
        if os.path.isfile(options.filename) == False:
            print 'Input file not exist or directory'
            parser.print_help()
            quit(-1)

        return (options.filename, options.savepayload, options.verbose, options.exitonerror)

    parser.print_help()
    quit(-1)

def GetRtpHeaderFromRtp(buf):
    rtp_header = {}
    byte1 = struct.unpack("B", buf[0])[0]
    rtp_header['version'] = (byte1&0xC0)>>6;
    rtp_header['padding'] = (byte1&0x20)>>5;
    rtp_header['extension'] = (byte1&0x10)>>4;
    rtp_header['csi_count'] = (byte1&0x0F);

    byte2 = struct.unpack("B", buf[1])[0]
    rtp_header['marker'] = (byte2&0x80)>>7;
    rtp_header['payload_type'] = (byte2&0x7F);

    byte34 = struct.unpack("!H", buf[2:4])[0]
    rtp_header['sequence_number'] = byte34

    byte5678 = struct.unpack("!I", buf[4:8])[0]
    rtp_header['timestamp']=byte5678

    byte9101112 = struct.unpack("!I", buf[8:12])[0]
    rtp_header['ssrc']=byte9101112

    return rtp_header

def parseRtp(inName, outCsvName,savepayload, outBinName, verbose, exitonerror):

    fBinOut=None
    if savepayload:
        fBinOut = open(outBinName,'wb')
    
    with open(inName,'rb') as fin:
        with  open(outCsvName,'wb') as fCsvOut:
            writer = csv.writer(fCsvOut)
            header = ['pts', 'systime_str', 'systime_ms']
            writer.writerow(header)

            payload_type=-1

            pcap = dpkt.pcap.Reader(fin)
            for ts, buf in pcap:
                systime_str=str(datetime.datetime.fromtimestamp(ts)) #datetime.datetime.fromtimestamp(ts)返回的是datetime.datetime类型
                ms=int(round(ts*1000))

                if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
                    l2pkt = dpkt.sll.SLL(buf)
                elif pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL2:
                    l2pkt = dpkt.sll2.SLL2(buf)
                else:
                    l2pkt = dpkt.ethernet.Ethernet(buf)
                ip = l2pkt.data
                udp = ip.data
                udppayload = udp.data

                rtp_header=GetRtpHeaderFromRtp(udppayload)

                errorFlag=False
                if rtp_header['payload_type'] <0 or rtp_header['payload_type']>127:
                    errorFlag=true

                if errorFlag:
                    if exitonerror:
                        print("payload type illegal, stop parse")
                        break
                    
                if errorFlag == False:
                    if payload_type<0:
                        payload_type=rtp_header['payload_type']
                        print("payload_type=",payload_type)
                    if rtp_header['payload_type']==payload_type:

                        #保存时间戳
                        pts=rtp_header['timestamp']
                        row=[str(pts),systime_str,ms]
                        writer.writerow(row)
                        if verbose:
                            print("systime_str=",systime_str, "rtp_header=",rtp_header)
                        
                        #保存rtp paylaod
                        if fBinOut:
                            if rtp_header['padding'] != 0:
                                print("padding field exist, not support save payload now")
                                break
                            if rtp_header['extension'] != 0:
                                print("extension field exist, not support save payload now")
                                break
                            if rtp_header['csi_count'] != 0:
                                print("csi_count=%d, not support save payload now"%(rtp_header['csi_count']))
                                break
                            rtp_payload=udppayload[12:len(udppayload)];
                            fBinOut.write(rtp_payload)

    if fBinOut:
        fBinOut.close()

    print("")
    print("finish parse %s, write to %s "%(inName,outCsvName))

if __name__ == '__main__':
    if sys.version_info.major > 2:  # this script for 2.x
        print 'Required Python version 2.x'
        quit(-1)

    filename, savepayload, verbose, exitonerror = parse_options()
    parseRtp(filename,"outrtp.csv",savepayload,"outrtp.bin",verbose, exitonerror)