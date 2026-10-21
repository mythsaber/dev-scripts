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
    该脚本适用于udpts pcap文件
    从pcap中解析抓包时刻点、ts流时间戳
    -m参数指定video，则从ts流中查找某一路视频pes，开始分析，忽略其它媒体
    -m参数指定audio，则从ts流中查找某一路音频pes，开始分析，忽略其它媒体
"""

"""
Usage:
  -i            input udpts pcap file
  -m            video or audio
  -v            verbose mode, print DTS, PTS and frame durations  (default false)
  -e            if set then exit once the first error detected  (default false)
"""

def parse_options():
    parser = OptionParser(
        usage="%prog [-i]  [-m]  [-e]  [-v]", version="%prog 1.0")

    parser.add_option("-i",
                      dest="filename",
                      help="input udp ts pcap file",
                      type="string",
                      action="store"
                      )

    parser.add_option("-m",
                      dest="mediatype",
                      help="media type  (default audio)",
                      type="string",
                      action="store",
                      default="audio")

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

    (options, args) = parser.parse_args()

    if options.filename:
        if os.path.isfile(options.filename) == False:
            print 'Input file not exist or directory'
            parser.print_help()
            quit(-1)

        return (options.filename, options.mediatype, options.verbose, options.exitonerror)

    parser.print_help()
    quit(-1)

def GetPesPid(pmtpid, buf, stremtype_list):
    #参数pmtpid为pmt表的pid，如果为-1，表示未知，需要当前函数自己查找
    #返回查找到的pmt pid和pes pid，-1表示未找到

    patFound = False if pmtpid<=0 else True
    pmtid = pmtpid
    eof = False
    tsPktStartPos = 0

    while True:  # pkt loop to find PSI
        curpos=tsPktStartPos
        if curpos+1>len(buf):
            eof = True
            break  # eof
        b = buf[curpos]
        curpos+=1

        syncByte = struct.unpack("B", b)[0]
        if syncByte != 0x47:
            print 'Error: not sync found at %x' % curpos
            return (pmtid,-1)

        if curpos+2>len(buf):
            eof = True
            break  # eof
        bb = buf[curpos:curpos+2]
        curpos+=2

        val = struct.unpack("!H", bb)[0]

        # extract pid
        payloadStart = (val & 0x4000) >> 14  # payload_unit_start_indicator
        pid = val & 0x1FFF

        if pid == 0 and patFound == False and payloadStart:  # PAT, payload_start=1 indicates that this is the start of PAT
            print("pat find")
            val = struct.unpack("B", buf[curpos])[0]
            curpos+=1
            adaptCtrl = (val & 0x30) >> 4
            if adaptCtrl == 0:
                print 'adaptation ctrl illegal, found at PAT'
                return (pmtid,-1)

            if adaptCtrl == 2:
                print 'no payload, found at PAT'
                return (pmtid,-1)

            if adaptCtrl == 3:
                adaptLen = struct.unpack("B", buf[curpos])[0]
                curpos+=1
                if adaptLen > 183:
                    print 'Adaptation header in PMT exceeds ts-packet'
                    return (pmtid,-1)
                # 在当前位置的基础上(第二个参数为1)，将文件读取指针移动adaptLen个字节
                curpos+=adaptLen
            
            ptrfld = struct.unpack("B", buf[curpos])[0]
            curpos+=1
            if ptrfld:
                curpos+=ptrfld

            tblid = struct.unpack("B", buf[curpos])[0]  # table_id
            curpos+=1
            if tblid != 0:
                print 'Illegal PAT table_id  %ld' % curpos
                return (pmtid,-1)

            val = struct.unpack("!H", buf[curpos:curpos+2])[0]
            curpos+=2
            sectLen = val & 0xfff
            if sectLen < 10:
                print 'Illegal PAT %ld' % curpos
                return (pmtid,-1)

            sectLen -= 9  # count CRC32, transport_id, version ...
            curpos+=5

            while True:
                if sectLen <= 0:
                    break

                progNum = struct.unpack("!H", buf[curpos:curpos+2])[0]
                curpos+=2
                val = struct.unpack("!H", buf[curpos:curpos+2])[0]
                curpos+=2
                pmtid = val & 0x1fff

                sectLen -= 4
                if progNum:
                    print("according to pat, pmt pid =%d" %pmtid)
                    break  # 查找到第一个节目后就停止

            patFound = True

        elif pid == pmtid and patFound == True and payloadStart:
            print("pmt found")
            val = struct.unpack("B", buf[curpos])[0]
            curpos+=1
            adaptCtrl = (val & 0x30) >> 4
            if adaptCtrl == 0:
                print 'adaptation ctrl illegal, found at PMT'
                return (pmtid,-1)

            if adaptCtrl == 2:
                print 'no payload, found at PMT'
                return (pmtid,-1)

            if adaptCtrl == 3:
                adaptLen = struct.unpack("B", buf[curpos])[0]
                curpos+=1
                if adaptLen > 183:
                    print 'Adaptation header in PMT exceeds ts-packet'
                    return (pmtid,-1)
                curpos+=1
            ptrfld = struct.unpack("B", buf[curpos])[0]
            curpos+=1
            if ptrfld:
                curpos+=ptrfld

            tblid = struct.unpack("B", buf[curpos])[0]  # table_id
            curpos+=1
            if tblid != 2:
                print 'Illegal PMT table_id  %ld' % curpos
                return (pmtid,-1)

            val = struct.unpack("!H", buf[curpos:curpos+2])[0]
            curpos+=2
            sectLen = val & 0xfff
            sectLen -= 4  # crc32

            val = struct.unpack("!H", buf[curpos:curpos+2])[0]  # prog num
            curpos+=2
            sectLen -= 2

            curpos+=3   # skip over version, section_num and etc.
            sectLen -= 3

            val = struct.unpack("!H", buf[curpos:curpos+2])[0]
            curpos+=2
            pcrpid = val & 0x1fff
            sectLen -= 2

            val = struct.unpack("!H", buf[curpos:curpos+2])[0]  # program_info_length
            curpos+=2
            sectLen -= 2
            progLen = val & 0xfff
            sectLen -= progLen

            if sectLen < 0:
                print 'Illegal PMT table_id  %ld' % curpos
                return (pmtid,-1)

            # ******** read out-loop descriptors *********
            while True:
                if progLen < 2:
                    break
                # read new descriptor
                descrTag = struct.unpack("B", buf[curpos])[0]
                curpos+=1
                descrLen = struct.unpack("B", buf[curpos])[0]
                curpos+=1
                progLen -= 2
                if progLen == 0:
                    break

                curpos+=descrLen
                progLen -= descrLen
            # ******** End out-loop descriptors *********

            while True:
                if sectLen < 5:
                    return (pmtid,-1)

                streamType = struct.unpack("B", buf[curpos])[0]
                curpos+=1
                streamPid = struct.unpack("!H", buf[curpos:curpos+2])[0]
                curpos+=2
                streamPid = streamPid & 0x1fff
                if streamType in stremtype_list:
                    return (pmtid,streamPid)

                infoLen = struct.unpack("!H", buf[curpos:curpos+2])[0]
                curpos+=2
                infoLen = infoLen & 0xfff
                sectLen -= infoLen
                if infoLen:
                    #   ****  in-loop descriptors ********
                    while True:
                        if infoLen < 2:
                            break
                        # read new descriptor
                        descrTag = struct.unpack("B", buf[curpos])[0]
                        curpos+=1
                        descrLen = struct.unpack("B", buf[curpos])[0]
                        curpos+=1
                        infoLen -= 2
                        if infoLen == 0:
                            break

                        curpos+=descrLen
                        infoLen -= descrLen

                    # ****  in-loop descriptors ********

                sectLen -= 5

            return (pmtid,-1)

        tsPktStartPos += 188

    return (pmtid,-1)

def GetVidPid(inName):
    # h264 h265 avs avs2 avs3
    video_stremtype_list = [0x1b, 0x24, 0x42, 0xd2, 0xd6] 

    with open(inName,'rb') as fin:
        pmtpid=-1
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
            tsdata = udp.data
            pmtpid, pespid=GetPesPid(pmtpid, tsdata,video_stremtype_list)
            if pespid>0:
                return pespid

    return -1

def GetAudPid(inName):

    # aac_adts aac_latm ac3 eac3 dts mp3
    audio_stremtype_list = [0x0f, 0x11, 0x06, 0x06, 0x85, 0x03]

    with open(inName,'rb') as fin:
        pmtpid=-1
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
            tsdata = udp.data
            pmtpid, pespid=GetPesPid(pmtpid, tsdata,audio_stremtype_list)
            if pespid>0:
                return pespid

    return -1

def ParsePtsDtsFromPesHeader(pkt_cnt, buf, pos):
    """
    Parse PES header to extract pts_dts_flag, pts and dts 
    if error then return (-1,0,0)
    """
    sc = struct.unpack("!I", buf[pos:pos+4])[0] #pes pkt start code prefix and stream id
    pos+=4
    pos+=3# skip over pesPktLen and next one byte 
    streamId = sc & 0xF0
    if streamId != 0xC0 and streamId != 0xD0 and streamId != 0xE0:
        print 'Unknown stream_id (0x%x) found at packet %d,  pos %x' % (streamId, pkt_cnt, pos)
        return (-1, 0, 0)

    # read pts_dts flag
    val = struct.unpack("B", buf[pos])[0]
    pos+=1
    ptsdts = val >> 6
    if ptsdts == 1:  # forbidden
        print 'PTS_DTS equal to 01 is forbidden'
        return (-1, 0, 0)

    peshdrLen = struct.unpack("B", buf[pos])[0]  # PES_header_data_length
    pos+=1
    pts = 0L
    dts = 0L

    if ptsdts == 2: #pts exist, dts not exist
        msb = struct.unpack("B", buf[pos])[0]
        pos+=1
        lsb = struct.unpack("!I", buf[pos:pos+4])[0]
        pos+=4
        pts = (lsb & 0xffff) >> 1
        pts = pts | ((lsb >> 17) << 15)
        pts = pts | (((msb & 0xE) >> 1) << 30)
        dts = pts
        peshdrLen -= 5
    elif ptsdts == 3: #pts and dts both exist
        msb = struct.unpack("B", buf[pos])[0]
        pos+=1
        lsb = struct.unpack("!I", buf[pos:pos+4])[0]
        pos+=4
        pts = (lsb & 0xffff) >> 1
        pts = pts | ((lsb >> 17) << 15)
        pts = pts | (((msb & 0xE) >> 1) << 30)

        msb = struct.unpack("B", buf[pos])[0]
        pos+=1
        lsb = struct.unpack("!I", buf[pos:pos+4])[0]
        pos+=4
        dts = (lsb & 0xffff) >> 1
        dts = dts | ((lsb >> 17) << 15)
        dts = dts | (((msb & 0xE) >> 1) << 30)
        peshdrLen -= 10

    if peshdrLen < 0:
        print 'Corrupted PES header, declared PES header length is too small'
        return (-1, 0, 0)

    return (ptsdts, pts, dts)

def GetDtsFromPcapUdpPayload(buf, mpid, statinfos,verbose):

    #buf为一个pcap包的udp payload
    #mpid为关注的pes的pid
    #statinfos是个list，包含[target_media_tspkt_cnt, tspkt_total_cnt, target_media_pespkt_cnt, timestamp_cnt, firstDts, prevDts]
    #函数返回一个list，其中每个元素是一个包含[error,dst,pts]的list，error指明是否有时间戳错误，如dts不递增
    target_media_tspkt_cnt = statinfos[0]
    tspkt_total_cnt = statinfos[1]
    target_media_pespkt_cnt = statinfos[2]
    timestamp_cnt = statinfos[3]
    firstDts = statinfos[4]
    prevDts = statinfos[5]

    curTsPktStartPos=0
    curpos = 0
    errorFlag = False

    timestamp_list=[]

    while(True):
        if curpos+1>len(buf):
            break;
        b = buf[curpos]
        curpos+=1;
        syncByte = struct.unpack("B", b)[0]
        if syncByte != 0x47:
            print 'not sync found at %x,  pkt  %d' % (curTsPktStartPos, tspkt_total_cnt)
            break
        
        if curpos+2>len(buf):
            break;
        bb = buf[curpos:curpos+2]
        curpos+=2
        val = struct.unpack("!H", bb)[0]

        # extract pid
        payloadStart = (val & 0x4000) >> 14  # payload_unit_start_indicator
        pid = val & 0x1FFF
        tshdr = 4  # minimal length of ts-header
   
        if pid != mpid:
            tspkt_total_cnt += 1
            curTsPktStartPos+=188
            curpos = curTsPktStartPos
        else:  # target media stream
            tspkt_total_cnt += 1
            target_media_tspkt_cnt += 1

            val = struct.unpack("B", buf[curpos])[0]
            curpos+=1
            adaptCtrl = (val & 0x30) >> 4
            if adaptCtrl == 0:
                print 'adaptation ctrl illegal, found at packet %d,  pos %x' % (tspkt_total_cnt, curTsPktStartPos)
                quit(-1)

            if adaptCtrl == 2:  # no payload
                curTsPktStartPos+=188
                curpos = curTsPktStartPos
                continue
            
            if (adaptCtrl == 1) or (adaptCtrl == 3): # payload only or adaptation + payload
                if adaptCtrl == 3:       
                    adaptLen = struct.unpack("B", buf[curpos])[0]
                    curpos+=1
                    payload = 184-adaptLen-1
                    if payload < 0:
                        print 'adaptation header too long, found at packet %d,  pos  0x%x' % (tspkt_total_cnt, curTsPktStartPos)
                        break
                    pesPos = curpos+adaptLen
                    curpos+=adaptLen
                    tshdr += adaptLen
                    if tshdr > 188:
                        print 'ts header is too long, found at packet %d,  pos  0x%x' % (tspkt_total_cnt, curTsPktStartPos)
                        quit(-1)
                
                if payloadStart:  # pes header is present
                    ptsdts, pts, dts = ParsePtsDtsFromPesHeader(tspkt_total_cnt,buf, curpos)
                    if ptsdts == -1:
                        quit(-1)
                    target_media_pespkt_cnt += 1
                    if ptsdts:
                        timestamp_cnt += 1
                        if firstDts:
                            firstDts = False
                            if verbose:
                                print 'DTS  %d ,    PTS   %d' % (dts, pts)
                        else:
                            if dts == prevDts:
                                print 'Error: previous and current DTS (%d) coincide, packet %d,  pos  0x%x' % (dts, tspkt_total_cnt, curTsPktStartPos)
                                errorFlag = True

                            diffInMs = float(dts-prevDts)/90.0
                            if verbose:
                                print 'DTS  %d ,    PTS   %d,  frame duration (ms)  %0.1f' % (dts, pts, diffInMs)
                        
                        prevDts = dts

                    if ptsdts == 3:
                        if dts > pts:
                            print 'Error: dts (%d) > pts (%d), packet %d,  pos  0x%x' % (dts, pts, tspkt_total_cnt, curTsPktStartPos)
                            errorFlag = True

                        if pts == dts:
                            print 'Error:  both pts and dts (%d) signaled and both equal, packet %d,  pos  0x%x' % (pts, tspkt_total_cnt, curTsPktStartPos)
                            errorFlag = True
               
                    timestamp_list.append([errorFlag, dts,pts])

                curTsPktStartPos+=188
                curpos = curTsPktStartPos
                continue

    statinfos[0]=target_media_tspkt_cnt
    statinfos[1]=tspkt_total_cnt
    statinfos[2]=target_media_pespkt_cnt
    statinfos[3]=timestamp_cnt
    statinfos[4]=firstDts
    statinfos[5]=prevDts

    return timestamp_list;

def parseTime(inName, media_pid, outName,verbose, exitonerror):

    target_media_tspkt_cnt = 0
    tspkt_total_cnt = 0
    target_media_pespkt_cnt = 0
    timestamp_cnt = 0
    firstDts = True
    prevDts = 0.0

    statinfos=[target_media_tspkt_cnt,tspkt_total_cnt,target_media_pespkt_cnt,timestamp_cnt,firstDts,prevDts]

    with open(inName,'rb') as fin:
        with  open(outName,'wb') as fout:
            writer = csv.writer(fout)
            header = ['dts', 'pts', 'systime']
            writer.writerow(header)

            pcap = dpkt.pcap.Reader(fin)
            for ts, buf in pcap:
                systime_str=str(datetime.datetime.fromtimestamp(ts))

                if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
                    l2pkt = dpkt.sll.SLL(buf)
                elif pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL2:
                    l2pkt = dpkt.sll2.SLL2(buf)
                else:
                    l2pkt = dpkt.ethernet.Ethernet(buf)
                ip = l2pkt.data
                udp = ip.data
                udppayload = udp.data

                
                # print("systime_str=%s,udppayload len=%d"%(systime_str,len(udppayload)))

                timestamp_list=GetDtsFromPcapUdpPayload(udppayload,media_pid,statinfos,verbose)

                #是否有时间戳错误，是否停止解析
                bStopParse=False
                for timestamp in timestamp_list:
                    errorFlag=timestamp[0]
                    if exitonerror and errorFlag:
                        bStopParse=True
                        break
                if bStopParse:
                    print("stop parse siince an timestamp error occur")
                    break;
                
                rows=[]
                for timestamp in timestamp_list:
                    errorFlag=timestamp[0]
                    dts=timestamp[1]
                    pts=timestamp[2]
                    if errorFlag==False:
                        rows.append([dts,pts,systime_str])
                if(len(rows)>0):
                    # print("rows=",rows)
                    writer.writerows(rows)

    target_media_tspkt_cnt = statinfos[0]
    tspkt_total_cnt = statinfos[1]
    target_media_pespkt_cnt = statinfos[2]
    timestamp_cnt = statinfos[3]
    firstDts = statinfos[4]
    prevDts = statinfos[5]
    
    print 'total ts-packets:    %d' % tspkt_total_cnt
    print 'target media ts packets:    %d' % target_media_tspkt_cnt
    print 'target media pes packets:   %d' % target_media_pespkt_cnt
    print 'pts\dts num:      %d' % timestamp_cnt

    print("")
    print("finish parse %s, write to %s "%(inName,outName))

if __name__ == '__main__':
    if sys.version_info.major > 2:  # this script for 2.x
        print 'Required Python version 2.x'
        quit(-1)

    filename, mediatype, verbose, exitonerror = parse_options()

    mpid = -1
    if mediatype == "video":
        mpid = GetVidPid(filename)
        print 'target video pid=%d' %mpid
        if mpid <= 0:
            print 'h264 or h265 or avs or avs2 or avs3 pid not found'
            quit(-1)
    elif mediatype == "audio":
        mpid = GetAudPid(filename)
        print 'target audio pid=%d' %mpid
        if mpid <= 0:
            print 'aac_adts or aac_latm or ac3 or eac3 or dts or mp3 pid not found'
            quit(-1)
    else:
        print 'only support video or audio media'
        quit(-1)
    
    parseTime(filename,mpid,"inpcap.csv",verbose, exitonerror)