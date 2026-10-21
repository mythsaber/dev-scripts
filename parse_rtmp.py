import sys
from optparse import OptionParser
from scapy.all import *

AMF_COMMAND = 0x14
AMF3_COMMAND = 0x11
AMF_STRING = 0x02
AMF_NUMBER = 0x00
AMF_OBJECT = 0x03
AMF_BOOLEAN = 0x01
AMF_NULL = 0x05

DEFAULT_MAX_CHUNK_BODY_SIZE=128

def parse_options():
    parser = OptionParser(
        usage="%prog [-i]  [-c] [--loglevel]", version="%prog 1.0")

    parser.add_option("-i",
                      dest="in_file_path",
                      help="input rtmp pcap file",
                      type="string",
                      action="store",
                      default=""
                      )

    parser.add_option("-p",
                      dest="server_port",
                      help="rtmp server listening port",
                      type="int",
                      action="store",
                      default=None
                      )

    parser.add_option("--loglevel",
                      dest="log_level",
                      help="verbose or debug",
                      type="string",
                      action="store",
                      default="debug")

    (options, _) = parser.parse_args()

    if(options.in_file_path==""):
        if(os.path.isfile(options.in_file_path) == False):
            print('[ERROR] input file not specified')
            parser.print_help()
            sys.exit()
    if(options.server_port==None):
            print('[DEBUG] server port not set, default 1935')
            options.server_port=1935
    return (options.in_file_path, options.server_port, options.log_level)

class ChunkRefInfo():
    def __init__(self):
        self.msg_stream_id=None
        self.timestamp=None
        self.timestamp_delta = None
        self.msg_len=None
        self.msg_type=None

class RtmpChunk():

    ref_chunks=dict()

    def __init__(self):
        self.fmt = None
        self.chunk_stream_id=None
        self.timestamp = None
        self.msg_len=None
        self.msg_type=None
        self.msg_stream_id=None
        self.header_len=0
        self.body_len=None
        self.body=bytearray()

    def parse_header(self, packet):
        if(len(packet)<14): #basic header最多3字节，msg header最多11字节
            print('[ERROR] lack data to parse chunk header, len={}'.format(len(packet)))
            sys.exit()

        self.fmt = (packet[0] & 0b11000000) >> 6
        self.chunk_stream_id = packet[0] & 0b00111111
        if(self.chunk_stream_id==0):
            print('[ERROR] not support 14 bit csid now')
            sys.exit()
        elif(self.chunk_stream_id==1):
            print('[ERROR] not support 22 bit csid now')
            sys.exit()

        if(self.fmt == 0): 
            cur_ts_delta=None
            self.timestamp = int.from_bytes(packet[1:4], byteorder='big')
            self.msg_len = int.from_bytes(packet[4:7], byteorder='big')
            self.msg_type = int.from_bytes(packet[7:8], byteorder='big')
            self.msg_stream_id = int.from_bytes(packet[8:12], byteorder='little')

            self.header_len = 12

        elif(self.fmt == 1):
            cur_ts_delta=int.from_bytes(packet[1:4], byteorder='big')
            self.timestamp = cur_ts_delta + RtmpChunk.ref_chunks[self.chunk_stream_id].timestamp
            self.msg_len = int.from_bytes(packet[4:7], byteorder='big')
            self.msg_type = int.from_bytes(packet[7:8], byteorder='big')
            self.msg_stream_id=RtmpChunk.ref_chunks[self.chunk_stream_id].msg_stream_id

            self.header_len = 8

        elif(self.fmt == 2):
            cur_ts_delta=int.from_bytes(packet[1:4], byteorder='big')
            self.timestamp = cur_ts_delta + RtmpChunk.ref_chunks[self.chunk_stream_id].timestamp
            self.msg_len = RtmpChunk.ref_chunks[self.chunk_stream_id].msg_len
            self.msg_type = RtmpChunk.ref_chunks[self.chunk_stream_id].msg_type
            self.msg_stream_id=RtmpChunk.ref_chunks[self.chunk_stream_id].msg_stream_id

            self.header_len = 4

        elif(self.fmt == 3):
            cur_ts_delta=None
            self.timestamp = RtmpChunk.ref_chunks[self.chunk_stream_id].timestamp
            self.msg_len = RtmpChunk.ref_chunks[self.chunk_stream_id].msg_len
            self.msg_type = RtmpChunk.ref_chunks[self.chunk_stream_id].msg_type
            self.msg_stream_id=RtmpChunk.ref_chunks[self.chunk_stream_id].msg_stream_id
               
            self.header_len = 1

        ref=ChunkRefInfo()
        ref.msg_stream_id=self.msg_stream_id
        ref.timestamp=self.timestamp
        ref.timestamp_delta = cur_ts_delta
        ref.msg_len=self.msg_len
        ref.msg_type=self.msg_type
        RtmpChunk.ref_chunks[self.chunk_stream_id]=ref

        return

    def set_body_len(self, length):
        if(self.body_len !=None):
            print('[ERROR] body length already set, len={}'.format(self.body_len))
            sys.exit()
        self.body_len=length
    
    def get_body_len(self):
        assert self.body_len !=None
        return self.body_len

    def get_body_lack_bytes(self):
        assert self.body_len!=None and self.body_len>0
        lack=self.body_len-len(self.body)
        assert lack>=0
        return lack
        
    def add_body_data(self, payload):
        self.body+=payload
        if(self.body_len==None or len(self.body) > self.body_len):
            print('[ERROR] too much data to add to chunk body, {}>{}'.format(len(self.body),self.body_len))
            sys.exit()
    
    def get_complete_body(self):
        assert self.get_body_lack_bytes()==0
        return self.body


class RtmpMsg():
    def __init__(self):
        self.msg_stream_id=None
        self.msg_type = None
        self.payload_len = 0
        self.timestamp=None
        self.body=bytearray()
        self.seq_no=None
    
    def init_header(self,chunk):
        self.msg_stream_id=chunk.msg_stream_id
        self.msg_type=chunk.msg_type
        self.payload_len=chunk.msg_len
        self.timestamp=chunk.timestamp

    def get_body_lack_bytes(self):
        assert self.payload_len>0
        lack=self.payload_len-len(self.body)
        assert lack>=0
        return lack

    def add_body_data(self,payload):
        self.body+=payload
        assert(len(self.body)<=self.payload_len)


class MsgManager():

    seq_no=0

    def __init__(self):
        self.msgs=dict()  #value is a list of RtmpMsg

    def find_msgs(self, msg_stream_id):
        if msg_stream_id in self.msgs:
            return self.msgs[msg_stream_id]
        else:
            return None
    
    def add_new_msg(self,msg):
        msg.seq_no=MsgManager.seq_no
        if msg.msg_stream_id in self.msgs:
            self.msgs[msg.msg_stream_id].append(msg)
        else:
            self.msgs[msg.msg_stream_id]=[msg]
        MsgManager.seq_no+=1
    
    def find_connect_msg(self):
        for msgid in self.msgs:
            msglist=self.msgs[msgid]
            for msg in msglist:
                if(msg.get_body_lack_bytes()==0):
                    if(msg.msg_type == AMF_COMMAND):
                        target=bytes([AMF_STRING,0x00,0x07]) + bytes('connect',encoding='utf-8')
                        if(msg.body.startswith(target)):
                            return msg
        return None

    def find_publish_msg(self):
        for msgid in self.msgs:
            msglist=self.msgs[msgid]
            for msg in msglist:
                if(msg.get_body_lack_bytes()==0):
                    if(msg.msg_type == AMF_COMMAND):
                        target = bytes([AMF_STRING,0x00,0x09]) +  bytes('FCPublish',encoding='utf-8')
                        if(msg.body.startswith(target)):
                            return msg
        return None

    def find_play_msg(self):
        for msgid in self.msgs:
            msglist=self.msgs[msgid]
            for msg in msglist:
                if(msg.get_body_lack_bytes()==0):
                    if(msg.msg_type == AMF_COMMAND):
                        target = bytes([AMF_STRING,0x00,0x04]) + bytes('play',encoding='utf-8')
                        if(msg.body.startswith(target)):
                            return msg
        return None

    def find_audio_msgs(self):
        retlist=[]
        for msgid in self.msgs:
            msglist=self.msgs[msgid]
            for msg in msglist:
                if(msg.get_body_lack_bytes()==0):
                    if(msg.msg_type == 8):
                        retlist.append(msg)
        return retlist

    def find_video_msgs(self):
        retlist=[]
        for msgid in self.msgs:
            msglist=self.msgs[msgid]
            for msg in msglist:
                if(msg.get_body_lack_bytes()==0):
                    if(msg.msg_type == 9):
                        retlist.append(msg)
        return retlist

    def remove_msg_seq_num_lessequal_than(self, seq):
        dic_keys_del=[]
        for msgid in self.msgs:
            msglist=self.msgs[msgid]
            end_idx=-1
            for idx,msg in enumerate(msglist):
                if(msg.get_body_lack_bytes()==0):
                    if(msg.seq_no<=seq):
                        end_idx=idx
                    else:
                        break
            if(end_idx>=0):
                del msglist[0:end_idx+1]
            if(len(msglist)==0):
                dic_keys_del.append(msgid)
        
        for key in dic_keys_del:
            self.msgs.pop(key)
    
    def remove_all_complete_msgs(self):
        dic_keys_del=[]
        for msgid in self.msgs:
            msglist=self.msgs[msgid]
            end_idx=-1
            for idx,msg in enumerate(msglist):
                if(msg.get_body_lack_bytes()==0):
                    end_idx=idx
                else:
                    break
            if(end_idx>=0):
                del msglist[0:end_idx+1]
            if(len(msglist)==0):
                dic_keys_del.append(msgid)
        
        for key in dic_keys_del:
            self.msgs.pop(key)

    def empty(self):
        return len(self.msgs)==0


class RtmpParser():
    def __init__(self,in_file_path,server_port,log_level):
        self.in_file_path=in_file_path
        self.server_port=server_port
        self.log_level=log_level
        
        self.stream=bytearray()

        self.handshake_found=False
        self.connect_found=False
        self.publish_found=False
        self.play_found=False
        self.src_ip=None
        self.dst_ip=None
        self.src_port=None
        self.dst_port=None

        self.chunk=None
        self.msg_manager=MsgManager()

        self.out_vid_bin_path=None
        self.out_vid_file_size=0
        self.out_aud_bin_path=None
        self.out_aud_file_size=0
        self.out_vid_csv_path=None
        self.out_aud_csv_path=None
    
    def start(self):
        pkts = rdpcap(self.in_file_path)
        self.parse_pcap(pkts)

    def save_audio_timestamp(self, pkt_ts, media_dts):
        if(self.out_aud_csv_path==None):
            abs_inpath=os.path.abspath(in_file_path)
            if(len(abs_inpath)>6 and in_file_path[-5:]=='.pcap'):
                self.out_aud_csv_path=abs_inpath[0:-5]+'_aud.csv'
            else:
                self.out_aud_csv_path=abs_inpath+'_aud.csv'
            if(os.path.exists(self.out_aud_csv_path)):
                print('[warn] audio out csv file already exist, will be override')
                os.remove(self.out_aud_csv_path)
            print('[info] start save audio timestamp to csv {}'.format(self.out_aud_csv_path))
            with open(self.out_aud_csv_path,mode='a') as fo:
                fo.write('time,dts\n')
        with open(self.out_aud_csv_path,mode='a') as fo:
            fo.write(pkt_ts+','+media_dts+'\n')

    def save_audio_es(self, payload):
        if(self.out_aud_bin_path==None):
            abs_inpath=os.path.abspath(in_file_path)
            if(len(abs_inpath)>6 and in_file_path[-5:]=='.pcap'):
                self.out_aud_bin_path=abs_inpath[0:-5]+'_aud.bin'
            else:
                self.out_aud_bin_path=abs_inpath+'_aud.bin'
            if(os.path.exists(self.out_aud_bin_path)):
                print('[warn] out file already exist, will be override')
                os.remove(self.out_aud_bin_path)
            print('[info] start save audio es to file {}'.format(self.out_aud_bin_path))
        with open(self.out_aud_bin_path,'ab') as fo:
            fo.write(payload)
            self.out_aud_file_size+=len(payload)

    def save_video_timestamp(self, pkt_ts, media_dts):
        if(self.out_vid_csv_path==None):
            abs_inpath=os.path.abspath(in_file_path)
            if(len(abs_inpath)>6 and in_file_path[-5:]=='.pcap'):
                self.out_vid_csv_path=abs_inpath[0:-5]+'_vid.csv'
            else:
                self.out_vid_csv_path=abs_inpath+'_vid.csv'
            if(os.path.exists(self.out_vid_csv_path)):
                print('[warn] video out csv file already exist, will be override')
                os.remove(self.out_vid_csv_path)
            print('[info] start save video timestamp to csv {}'.format(self.out_vid_csv_path))
            with open(self.out_vid_csv_path,mode='a') as fo:
                fo.write('time,dts\n')
        with open(self.out_vid_csv_path,mode='a') as fo:
            fo.write(pkt_ts+','+media_dts+'\n')

    def save_video_es(self, payload):
        if(self.out_vid_bin_path==None):
            abs_inpath=os.path.abspath(in_file_path)
            if(len(abs_inpath)>6 and in_file_path[-5:]=='.pcap'):
                self.out_vid_bin_path=abs_inpath[0:-5]+'_vid.bin'
            else:
                self.out_vid_bin_path=abs_inpath+'_vid.bin'
            if(os.path.exists(self.out_vid_bin_path)):
                print('[warn] out file already exist, will be override')
                os.remove(self.out_vid_bin_path)
            print('[info] start save video es to file {}'.format(self.out_vid_bin_path))
        with open(self.out_vid_bin_path,'ab') as fo:
            fo.write(payload)
            self.out_vid_file_size+=len(payload)

    def parse_stream_to_chunk_message(self):
        if(self.chunk==None):
            expected_stream_len=14
        else:
            assert self.chunk.get_body_lack_bytes()>0
            expected_stream_len = self.chunk.get_body_lack_bytes()

        while(len(self.stream) >= expected_stream_len):
            if(self.chunk==None):
                #解析chunk
                self.chunk=RtmpChunk()
                self.chunk.parse_header(self.stream)

                #获取对应的message
                msglist=self.msg_manager.find_msgs(self.chunk.msg_stream_id)
                if(msglist==None or msglist[-1].get_body_lack_bytes()==0):
                    curmsg=RtmpMsg()
                    curmsg.init_header(self.chunk)
                    self.msg_manager.add_new_msg(curmsg)
                else:
                    curmsg=msglist[-1]
                msg_lack_len=curmsg.get_body_lack_bytes()
                
                #确定chunk body长度
                if(msg_lack_len<=DEFAULT_MAX_CHUNK_BODY_SIZE):
                    self.chunk.set_body_len(msg_lack_len)
                else:
                    self.chunk.set_body_len(DEFAULT_MAX_CHUNK_BODY_SIZE)

                #填充chunk body
                start_idx=self.chunk.header_len
                end_idx=start_idx+self.chunk.get_body_len()
                self.chunk.add_body_data(self.stream[start_idx : end_idx])  #切片范围可能越界
                #移除stream中已解析的字节
                self.stream=self.stream[end_idx:]
            else:
                assert self.chunk.get_body_lack_bytes()>0
                #填充chunk body
                start_idx=0
                end_idx=self.chunk.get_body_lack_bytes()
                self.chunk.add_body_data(self.stream[start_idx : end_idx])  #切片范围可能越界
                #移除stream中已解析的字节
                self.stream=self.stream[end_idx:]

            #判断chunk是否已完整，如果完整则添加到message
            if(self.chunk.get_body_lack_bytes()==0):
                msglist=self.msg_manager.find_msgs(self.chunk.msg_stream_id)
                assert msglist!=None and len(msglist)>0
                curmsg=msglist[-1]
                curmsg.add_body_data(self.chunk.get_complete_body())
                self.chunk=None
                expected_stream_len=14
                continue
            else:
                expected_stream_len=self.chunk.get_body_lack_bytes()
                continue

    def find_connect_publish_play_cmd(self, packet):
        if packet.haslayer('TCP') and packet.haslayer("Raw"):
            if(packet["TCP"].sport != self.server_port and packet["TCP"].dport != self.server_port):
                return
            
            pkt_timestamp_str=str(datetime.fromtimestamp(float(packet.time)).strftime(r'%Y%m%d_%H%M%S_%f'))

            if(self.src_ip==None):
                self.src_ip=packet['IP'].src
                self.dst_ip=packet['IP'].dst
                self.src_port=packet['TCP'].sport
                self.dst_port=packet['TCP'].dport
                print('[DEBUG] chosen src addr={}:{}, dst addr={}:{}, pcap timestamp={}'.format(self.src_ip, self.src_port, self.dst_ip, self.dst_port, pkt_timestamp_str))
            
            if(packet['IP'].src!=self.src_ip or packet['TCP'].sport!=self.src_port or packet['IP'].dst!=self.dst_ip or packet['TCP'].dport!=self.dst_port):
                return
            
            self.stream+=bytearray(packet.load)
            
            if(self.handshake_found==False):
                if(len(self.stream) >= 1537+1536):
                    self.handshake_found=True
                    print('[DEBUG] handshake C0 C1 C2 found, pcap timestamp={}'.format(pkt_timestamp_str))
                    self.stream=self.stream[1536*2+1:]
                else:
                    return
            
            self.parse_stream_to_chunk_message()

            if(self.connect_found==False):
                msg=self.msg_manager.find_connect_msg()
                if(msg!=None):
                    print('[DEBUG] connect cmd found')
                    self.connect_found=True
                    self.msg_manager.remove_msg_seq_num_lessequal_than(msg.seq_no)
                else:
                    self.msg_manager.remove_all_complete_msgs()
                    return
            
            if(self.publish_found == False and self.play_found==False):
                pub_msg=self.msg_manager.find_publish_msg()
                if(pub_msg!=None):
                    print('[DEBUG] publish cmd found, pcap timestamp={}'.format(pkt_timestamp_str))
                    self.publish_found=True
                    self.msg_manager.remove_msg_seq_num_lessequal_than(pub_msg.seq_no)
                    return

                play_msg=self.msg_manager.find_play_msg()   
                if(play_msg!=None):
                    print('[DEBUG] play cmd found, pcap timestamp={}'.format(pkt_timestamp_str))
                    self.play_found=True
                    self.msg_manager.remove_msg_seq_num_lessequal_than(play_msg.seq_no)
                    return
                
                self.msg_manager.remove_all_complete_msgs()
        
    def parse_pcap(self, pkts):
        for packet in pkts:
            if(self.connect_found==False or (self.publish_found==False and self.play_found==False)):
                self.find_connect_publish_play_cmd(packet)
                if(self.connect_found==False or (self.publish_found==False and self.play_found==False)):
                    continue
                else:
                    assert len(self.stream)==0
                    # assert self.msg_manager.empty()
                    assert self.chunk==None
                    continue
            
            if packet.haslayer('TCP') and packet.haslayer('Raw'):
                if(self.publish_found):
                    if(packet['IP'].src!=self.src_ip or packet['TCP'].sport!=self.src_port or packet['IP'].dst!=self.dst_ip or packet['TCP'].dport!=self.dst_port):
                        continue
                elif(self.play_found):
                    if(packet['IP'].src!=self.dst_ip or packet['TCP'].sport!=self.dst_port or packet['IP'].dst!=self.src_ip or packet['TCP'].dport!=self.src_port):
                        continue
                
                pkt_timestamp_str=str(datetime.fromtimestamp(float(packet.time)).strftime(r'%Y%m%d_%H%M%S_%f'))
                
                self.stream+=bytearray(packet.load)
                self.parse_stream_to_chunk_message()
                
                audio_msgs=self.msg_manager.find_audio_msgs()
                for msg in audio_msgs:
                    self.save_audio_timestamp(pkt_timestamp_str,str(msg.timestamp))
                    if(self.log_level=='verbose'):
                        print('pcap ts={}, audio dts={}'.format(pkt_timestamp_str,msg.timestamp))
                
                video_msgs=self.msg_manager.find_video_msgs()
                for msg in video_msgs:
                    self.save_video_timestamp(pkt_timestamp_str,str(msg.timestamp))
                    if(self.log_level=='verbose'):
                        print('pcap ts={}, video dts={}'.format(pkt_timestamp_str,msg.timestamp))
                
                self.msg_manager.remove_all_complete_msgs()


if __name__ == '__main__':
    if sys.version_info.major < 3:
        print('[ERRRO] required Python version 3.x')
        sys.exit()

    in_file_path, server_port, log_level = parse_options()
    
    if False:
        in_file_path=r'C:\Users\myth\Desktop\rtmp_play.pcap'
        server_port=1935
        log_level='verbose'

    parser=RtmpParser(in_file_path,server_port,log_level)
    parser.start()