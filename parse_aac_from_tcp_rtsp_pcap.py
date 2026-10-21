# -*- coding: utf-8 -*-
import sys
import re
from optparse import OptionParser
from scapy.all import *

in_file_path=None
aac_channel_id=None
sample_rate=None
channel_num=None
aac_profile=None
log_level='debug'

option_found=False
rtsp_url=None
src_ip=None
dst_ip=None
src_port=None
dst_port=None
announce_found=False
play_found=False

out_file_path=None
out_file_size=0
last_tcp_left_payload=bytearray()

def parse_options():
    parser = OptionParser(
        usage="%prog [-i]  [-c] [--ar]  [--ac]  [--ap] [--loglevel]", version="%prog 1.0")

    parser.add_option("-i",
                      dest="in_file_path",
                      help="input aac rtsp over tcp pcap file",
                      type="string",
                      action="store",
                      default=""
                      )

    parser.add_option("-c",
                      dest="channel_id",
                      help="aac channel id in rtsp interleaved frame",
                      type="int",
                      action="store",
                      default=None
                      )

    parser.add_option("--ar",
                      dest="sample_rate",
                      help="sample rate need to be specified when no adts exist, very likely need to be set 1/2 real sample rate",
                      type="int",
                      action="store",
                      default=None)

    parser.add_option("--ac",
                      dest="channel_num",
                      help="channel num need to be specified when no adts exist",
                      type="int",
                      action="store",
                      default=None)

    parser.add_option("--ap",
                      dest="aac_profile",
                      help="aac profile need to be specified when no adts exist: 0 for aac main, 1 for aac lc, 2 for aac scalabel sample rate",
                      type="int",
                      action="store",
                      default=None)

    parser.add_option("--loglevel",
                      dest="log_level",
                      help="log level, can be verbose or debug",
                      type="string",
                      action="store",
                      default="debug")

    (options, _) = parser.parse_args()

    if(options.in_file_path==""):
        if(os.path.isfile(options.in_file_path) == False):
            print('[ERROR] input file not specified')
            parser.print_help()
            sys.exit()
    if(options.channel_id==None):
            print('[WARN] aac channel id not set, so will be auto detected, plz pay attention to the detection result')
    return (options.in_file_path, options.channel_id, options.sample_rate, options.channel_num, options.aac_profile, options.log_level)

def find_option_announce_play_cmd(packet):
    global option_found
    global rtsp_url
    global src_ip
    global dst_ip
    global src_port
    global dst_port
    global announce_found
    global play_found
    if packet.haslayer('TCP'):
        tcp_payload_str=bytes(packet['TCP'].payload)
        # 寻找OPTION
        if(not option_found):
            re_str=rb".*OPTIONS (rtsp://.*:[0-9]+).*"
            match_ret=re.findall(re_str, tcp_payload_str)
            if(len(match_ret)>0):
                option_found=True
                rtsp_url=match_ret[0].decode()
                src_ip=packet['IP'].src
                dst_ip=packet['IP'].dst
                src_port=packet['TCP'].sport
                dst_port=packet['TCP'].dport
                pkt_timestamp_str=str(datetime.fromtimestamp(float(packet.time)).strftime(r'%Y%m%d_%H%M%S_%f'))
                print('[INFO] packet timestamp={}, rtsp OPTION cmd found, tcp link=({}:{})->({}:{}), rtsp url={}'.format(pkt_timestamp_str,src_ip,src_port,dst_ip,dst_port,rtsp_url))
        #寻找announce或play
        if(announce_found==False and play_found==False):
            if(packet['IP'].src==src_ip and packet['TCP'].sport==src_port and packet['IP'].dst==dst_ip and packet['TCP'].dport==dst_port):
                # 寻找announce
                re_str=rb".*ANNOUNCE (rtsp://.*:[0-9]+).*"
                match_ret=re.findall(re_str, tcp_payload_str)
                if(len(match_ret)==1):
                    announce_found=True
                    pkt_timestamp_str=str(datetime.fromtimestamp(float(packet.time)).strftime(r'%Y%m%d_%H%M%S_%f'))
                    print('[INFO] packet timestamp={}, rtsp ANNOUNCE cmd found'.format(pkt_timestamp_str))
                    return
                # 寻找play
                re_str=rb".*PLAY (rtsp://.*:[0-9]+).*"
                match_ret=re.findall(re_str, tcp_payload_str)
                if(len(match_ret)==1):
                    play_found=True
                    pkt_timestamp_str=str(datetime.fromtimestamp(float(packet.time)).strftime(r'%Y%m%d_%H%M%S_%f'))
                    print('[INFO] packet timestamp={}, rtsp PLAY cmd found'.format(pkt_timestamp_str))
                    return            

def is_rtcp(rtp_or_rtsp_packet):
    #区分rtp和rtsp
    ptype = rtp_or_rtsp_packet[1] & 0b01111111
    if(ptype >=72 and ptype <=95):#https://en.wikipedia.org/wiki/RTP_payload_formats
        return True
    else:
        return False

def parse_rtp_header(packet):
    if(len(packet)<12):
        print('[error] not valid rtp packet, len<12')
        return None
    else:
        version = (packet[0] & 0b11000000) >> 6
        padding = (packet[0] & 0b00100000) >> 5
        extension = (packet[0] & 0b00010000) >> 4
        csrc_count = packet[0] & 0b00001111
        marker = (packet[1] & 0b10000000) >> 7
        payload_type = packet[1] & 0b01111111
        sequence_number = int.from_bytes(packet[2:4], byteorder='big')
        timestamp = int.from_bytes(packet[4:8], byteorder='big')
        ssrc = int.from_bytes(packet[8:12], byteorder='big')
        csrc_list = []
        if(csrc_count > 0):
            if(len(packet)<12 + csrc_count*4):
                print('[error] not valid rtp packet, csrs count={}, but packet len={}'.format(csrc_count,len(packet)))
                return None
            else:
                for i in range(csrc_count):
                    csrc = int.from_bytes(packet[12+i*4:16+i*4], byteorder='big')
                    csrc_list.append(csrc)
        
        header_extension_profile=None
        extension_header_data=None
        if extension:
            if(len(packet)<16+csrc_count*4):
                print('[error] not valid rtp packet, csrs count={}, extension={}, but but packet len={}'.format(csrc_count,extension,len(packet)))
                return None
            else:
                header_extension_profile = int.from_bytes(packet[12+csrc_count*4:14+csrc_count*4], byteorder='big')
                header_extension_length = int.from_bytes(packet[14+csrc_count*4:16+csrc_count*4], byteorder='big')
                header_extension_length *= 4
                if(len(packet)<16+csrc_count*4+header_extension_length):
                    print('[error] not valid rtp packet, csrs count={}, extension len={}, but but packet len={}'.format(csrc_count,header_extension_length,len(packet)))
                    return None
                else:
                    extension_header_data = packet[16+csrc_count*4:16+csrc_count*4+header_extension_length]
        if(extension):
            rtp_header_len=12+csrc_count*4+4+header_extension_length
        else:
            rtp_header_len=12+csrc_count*4

        return rtp_header_len, version, padding, extension, csrc_count, marker, payload_type, sequence_number, timestamp, ssrc, csrc_list, header_extension_profile, extension_header_data

def get_auheader_section_length(buf):
    length = 2;
    auheader_length = buf[0] << 8;
    auheader_length |= buf[1];
    length += auheader_length/8;
    return int(length)

def generate_adts_header(sampling_rate, channels, obj_type, frame_length):
    freq_index = {
        96000: 0,
        88200: 1,
        64000: 2,
        48000: 3,
        44100: 4,
        32000: 5,
        24000: 6,
        22050: 7,
        16000: 8,
        12000: 9,
        11025: 10,
        8000: 11,
        7350: 12
    }[sampling_rate]
    adts_header=bytearray(7)
    adts_header[0] = 0xff  # syncword
    adts_header[1] = 0xf1  # MPEG-4, Layer (0), No CRC
    adts_header[2] = obj_type << 6;
    adts_header[2] |= (freq_index << 2);
    adts_header[2] |= (channels & 0x4) >> 2;
    adts_header[3] = (channels & 0x3) << 6;
    adts_header[3] |= (frame_length & 0x1800) >> 11;
    adts_header[4] = (frame_length & 0x1FF8) >> 3
    adts_header[5] = (frame_length & 0x7) << 5
    adts_header[5] |= 0x1F
    adts_header[6] = 0xfc  # No ID, No layer, protection absent
    adts_header[6] |= 0 & 0x03; 
    return adts_header

def save_audio_es(payload):
    global out_file_path
    global out_file_size
    if(out_file_path==None):
        abs_inpath=os.path.abspath(in_file_path)
        if(len(abs_inpath)>6 and in_file_path[-5:]=='.pcap'):
            out_file_path=abs_inpath[0:-5]+'.aac'
        else:
            out_file_path=abs_inpath+'.aac'
        if(os.path.exists(out_file_path)):
            print('[warn] out file already exist, will be override')
            os.remove(out_file_path)
        print('[info] start save aac to file {}'.format(out_file_path))
    with open(out_file_path,'ab') as fo:
        fo.write(payload)
        out_file_size+=len(payload)
        if(log_level=='verbose'):
            print("[VERBOSE] write {} bytes to file".format(len(payload)));

def parse_aac_from_rtp_payload(payload,pkt_time):
    global last_tcp_left_payload
    if (len(payload) < 2):
        pkt_timestamp_str=str(datetime.fromtimestamp(float(pkt_time)).strftime(r'%Y%m%d_%H%M%S_%f'))
        print("[error] pkt timestamp={}, rtp aac payload len too small={}".format(pkt_timestamp_str,len(payload)))
        return
    if (payload[0] == 0xff and (payload[1] >> 4) == 0xf):
        #adts header first 12 bit is 0xfff
        #not exist au_header_section
        au_header_section_len=0
    else:
        au_header_section_len = get_auheader_section_length(payload)
        if(len(payload)<au_header_section_len):
            pkt_timestamp_str=str(datetime.fromtimestamp(float(pkt_time)).strftime(r'%Y%m%d_%H%M%S_%f'))
            print('[error] pkt timestamp={}, invalid au header section len={}, rtp aac paylaod len={}'.format(pkt_timestamp_str,au_header_section_len,len(payload)))
            return
    if (au_header_section_len == 0):
        if (payload[0] == 0xff and (payload >> 4) == 0xf):# 有adts头
            save_audio_es(payload);
            return
        else:
            pkt_timestamp_str=str(datetime.fromtimestamp(float(pkt_time)).strftime(r'%Y%m%d_%H%M%S_%f'))
            print("[error] pkt timestamp={}, au header section len=0, and no adts header".format(pkt_timestamp_str));
            return
    else:
        auheads_total_len = au_header_section_len - 2;
        if (auheads_total_len <= 0 or auheads_total_len % 2 != 0):
            pkt_timestamp_str=str(datetime.fromtimestamp(float(pkt_time)).strftime(r'%Y%m%d_%H%M%S_%f'))
            print("[error] pkt timestamp={}, auheads total len not valid: {}".format(pkt_timestamp_str,auheads_total_len));
            return;
        au_num = int(auheads_total_len / 2)
        parsed_len = au_header_section_len;
        out_buf = bytearray()
        for i in range(au_num):
            cur_auhead = payload[2+i*2 : 2+i*2+2];
            au_len = (cur_auhead[0] << 5) | (cur_auhead[1] >> 3);
            if (au_len + parsed_len > len(payload)):
                pkt_timestamp_str=str(datetime.fromtimestamp(float(pkt_time)).strftime(r'%Y%m%d_%H%M%S_%f'))
                print("[error] pkt timestamp={}, au len error, au_len={}, parsed_len={},  rtp payload len={}".format(pkt_timestamp_str, au_len, parsed_len, len(payload)));
                return
            cur_au = payload[parsed_len:parsed_len+au_len]

            if (au_len >= 2 and cur_au[0] == 0xff and (cur_au[1] >> 4) == 0xf):
                #adts头已经存在
                out_buf+=cur_au
                parsed_len += au_len;
            else:
                #无adts头
                if(sample_rate==None or channel_num==None or aac_profile==None):
                    pkt_timestamp_str=str(datetime.fromtimestamp(float(pkt_time)).strftime(r'%Y%m%d_%H%M%S_%f'))
                    print("[error] pkt timestamp={}, no adts header exist, plz set ar ac ap manually".format(pkt_timestamp_str))
                    sys.exit()
                else:
                    adts_header=generate_adts_header(sample_rate, channel_num, aac_profile, au_len + 7);
                    out_buf+=adts_header
                    out_buf+=cur_au
                    parsed_len += au_len;
            if (i == au_num - 1):
                if (parsed_len < len(payload)):
                    #tcp是流式的，因此上层rtsp的protocol data unit可能在tcp层被拆分
                    last_tcp_left_payload+=payload[parsed_len:]
                    pkt_timestamp_str=str(datetime.fromtimestamp(float(pkt_time)).strftime(r'%Y%m%d_%H%M%S_%f'))
                    print("[DEBUG] pkt timestamp={}, all au parsed, still tcp segment data left, parsed len={}, left len={}, total {} au in packet".format(pkt_timestamp_str, parsed_len, len(payload), au_num));

        if (len(out_buf) > 0):
            save_audio_es(out_buf);

def parse_pcap(pkts):
    global aac_channel_id
    global last_tcp_left_payload
    for packet in pkts:
        if(option_found==False or (announce_found==False and play_found==False)):
            find_option_announce_play_cmd(packet)
            if(option_found==False or (announce_found==False and play_found==False)):
                continue
        if packet.haslayer('TCP'):
            if(announce_found):
                if(packet['IP'].src!=src_ip or packet['TCP'].sport!=src_port or packet['IP'].dst!=dst_ip or packet['TCP'].dport!=dst_port):
                    continue
            if(play_found):
                if(packet['IP'].src!=dst_ip or packet['TCP'].sport!=dst_port or packet['IP'].dst!=src_ip or packet['TCP'].dport!=src_port):
                    continue
            pkt_timestamp_str=str(datetime.fromtimestamp(float(packet.time)).strftime(r'%Y%m%d_%H%M%S_%f'))
            if(log_level=='verbose'):
                print('[VERBOSE] packet timestamp:{}={}'.format(packet.time,pkt_timestamp_str))
            tcp_payload = bytes(packet['TCP'].payload)
            if(len(last_tcp_left_payload)>0):
                tcp_payload=last_tcp_left_payload+tcp_payload
                last_tcp_left_payload=bytearray()
            if(len(tcp_payload)>4):
                if(tcp_payload[0] == 0x24):# rtsp interleave frame 0x26 is '$'
                    cur_channel_id=tcp_payload[1]
                    if(aac_channel_id == None):
                        aac_channel_id=cur_channel_id
                        print('[WARN] aac channel id auto detection result is {}, if not right, plz specify manually'.format(aac_channel_id))
                    else:
                        if(cur_channel_id !=aac_channel_id):
                            continue
                    cur_rtp_or_rtcp_len=tcp_payload[2]<<8 | tcp_payload[3]
                    if(is_rtcp(tcp_payload[4:])):
                        print('[INFO] packet timestamp={}, include a rtcp pkt'.format(pkt_timestamp_str))
                        if(len(tcp_payload)<4+cur_rtp_or_rtcp_len):
                            print('[ERROR] packet timestamp={}, current program not supported scene: part of rtcp in next tcp message'.format(pkt_timestamp_str))
                            sys.exit()
                        elif(len(tcp_payload)==4+cur_rtp_or_rtcp_len):
                            continue
                        else:
                            tcp_payload=tcp_payload[4+cur_rtp_or_rtcp_len:]
                        continue
                    rtp_packet = tcp_payload[4:]
                    rtp_header=parse_rtp_header(rtp_packet)
                    if(rtp_header==None):
                        return
                    else:
                        # print('[DEBUG] rtp_header: ',rtp_header[0:-1])
                        rtp_header_len, version, padding, extension, csrc_count, marker, payload_type, sequence_number, timestamp, ssrc, csrc_list, header_extension_profile, extension_header_data=rtp_header
                    rtp_payload = rtp_packet[rtp_header_len:]
                    parse_aac_from_rtp_payload(rtp_payload,packet.time)


if __name__ == '__main__':
    if sys.version_info.major < 3:
        print('Required Python version 3.x')
        sys.exit()
    
    in_file_path, aac_channel_id, sample_rate, channel_num, aac_profile, log_level= parse_options()

    # in_file_path= 'C:\\Users\\myth\\Desktop\\vlc_tcp_play_aac.pcap'
    # aac_channel_id=0
    # sample_rate=44100
    # channel_num=2
    # aac_profile=1

    pkts = rdpcap(in_file_path)
    parse_pcap(pkts)
    if(out_file_path!=None):
        print('[INFO] parse finished, out file size={} byte={} kB'.format(out_file_size,out_file_size/1000))
