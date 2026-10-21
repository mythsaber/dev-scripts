# encoding:utf-8
import sys
import os
import struct
import csv
import datetime
from optparse import OptionParser

filename=None
channels=None
sample_byte=None
frame_size=None

def parse_options():
    parser = OptionParser(
        usage="%prog [-i]  [--ac]  [--sample_byte]  [--frame_size]", version="1.0")

    parser.add_option("-i",
                      dest="filename",
                      help="input planar pcm data file",
                      type="string",
                      action="store"
                      )

    parser.add_option("--ac",
                      dest="channels",
                      help="audio channel num",
                      type="int",
                      action="store",
                      default=None)

    parser.add_option("--sample_byte",
                      dest="sample_byte",
                      help="byte per sample, eg. 2 for s16le",
                      type="int",
                      action="store",
                      default=False)

    parser.add_option("--frame_size",
                      dest="frame_size",
                      help="byte per planar audio frame",
                      type="int",
                      action="store",
                      default=None)                 

    (options, _) = parser.parse_args()

    if(options.filename==None or options.channels==None or options.sample_byte==None or options.frame_size==None):
        print('[ERROR] plz input param')
        parser.print_help()
        sys.exit()
    
    return (options.filename, options.channels, options.sample_byte, options.frame_size)

def convert_planar_audio_to_packed(filename, channels, sample_byte, frame_size):
    if(channels<=0 or sample_byte<=0 or frame_size<=0 or frame_size%channels!=0 or frame_size%sample_byte!=0 or frame_size%(channels*sample_byte)!=0):
        print('[error] invalid param, plz check')
        return
    
    abs_inpath=os.path.abspath(filename)
    out_bin_path=abs_inpath+'.packed'
    if(os.path.exists(out_bin_path)):
        print('[warn] out file already exist, will be override')
        os.remove(out_bin_path)
    print('[info] start save converted packed pcm to file {}'.format(out_bin_path))

    with open(filename,'rb') as fin:
        with open(out_bin_path,'wb') as fo:
            read_byte=0
            channel_offset=[]
            for ch in range(channels):
                offset=int(ch*(frame_size/channels))
                channel_offset.append(offset)

            while(True):
                frame=fin.read(frame_size)
                if(len(frame)<frame_size):
                    print('[debug] finish convert, total convert {} bytes, left {} bytes'.format(read_byte,len(frame)))
                    return
                read_byte+=len(frame)
                for idx in range(int(frame_size/sample_byte/channels)):
                    for ch in range(channels):
                        start=channel_offset[ch]+idx*sample_byte
                        fo.write(frame[start:start+sample_byte])
            

if __name__ == '__main__':
    if sys.version_info.major < 3:
        print('[ERRRO] required Python version 3.x')
        sys.exit()

    filename, channels, sample_byte, frame_size = parse_options()

    if(False):
        filename=r'C:\Users\myth\Desktop\planar.raw'
        channels=2
        sample_byte=4
        frame_size=8192
        
    convert_planar_audio_to_packed(filename, channels, sample_byte, frame_size)