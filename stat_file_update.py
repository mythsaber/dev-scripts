#!/usr/bin/env python3
import os
import time
import sys
from optparse import OptionParser

def parse_options():
    parser = OptionParser(usage="%prog [-i]", version="1.0")

    parser.add_option("-i",
                      dest="filename",
                      help="stat file name",
                      type="string",
                      action="store"
                      )           

    (options, _) = parser.parse_args()

    if(options.filename==None):
        print('[ERROR] plz input file name')
        parser.print_help()
        sys.exit()
    
    return (options.filename)

if __name__ == '__main__':
    last_mtime = 0
    filename = parse_options()
    while True:
        try:
            current_mtime = os.path.getmtime(filename)
            if(current_mtime != last_mtime):
                if(last_mtime != 0):
                    interval = (current_mtime - last_mtime) * 1000  # 转换为毫秒
                    print("更新间隔: {:.2f}ms - 时间: {}".format(interval, time.strftime('%H:%M:%S')))
                last_mtime = current_mtime
        except FileNotFoundError:
            pass
        time.sleep(0.001)  # 1ms 精度