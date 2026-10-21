import struct
import csv
import sys

def parse_ts_file(input_file, output_csv):
    PACKET_SIZE = 188
    SYNC_BYTE = 0x47

    with open(input_file, 'rb') as f, open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Packet_Index', 'PID', 'PTS', 'DTS'])

        packet_count = 0
        while True:
            data = f.read(PACKET_SIZE)
            if not data or len(data) < PACKET_SIZE:
                break
            
            if data[0] != SYNC_BYTE:
                # 如果没对齐，尝试找下一个同步点（简单鲁棒性处理）
                continue

            # 1. 提取 PID (13 bits)
            # data[1] 的低5位 + data[2] 全8位
            pid = ((data[1] & 0x1F) << 8) | data[2]

            # 2. 检查 Payload Unit Start Indicator (PUSI)
            # 只有 PUSI=1 的包才可能包含 PES 头部（即 PTS/DTS）
            pusi = (data[1] >> 6) & 0x01
            
            # 3. 计算负载起始位置 (跳过 Adaptation Field)
            adaptation_field_control = (data[3] >> 4) & 0x03
            payload_start = 4
            if adaptation_field_control in [2, 3]: # 有自适应字段
                af_length = data[4]
                payload_start += 1 + af_length

            # 4. 如果是 PUSI 且有负载，尝试解析 PES 头部
            if pusi and payload_start < PACKET_SIZE:
                payload = data[payload_start:]
                
                # 检查 PES 起始码 0x000001
                if len(payload) > 9 and payload[:3] == b'\x00\x00\x01':
                    stream_id = payload[3]
                    # 排除非媒体流 (如 Program Stream Map 等)
                    if stream_id >= 0xBC:
                        flags = payload[7]
                        pts_dts_flag = (flags >> 6) & 0x03
                        
                        pts, dts = None, None
                        
                        # 解析 PTS
                        if pts_dts_flag >= 2: # 10 (仅PTS) 或 11 (有PTS和DTS)
                            pts = parse_timestamp(payload[9:14])
                        
                        # 解析 DTS
                        if pts_dts_flag == 3: # 11
                            dts = parse_timestamp(payload[14:19])
                        
                        if pts is not None and dts is None:
                            dts = pts
                        
                        if pts is not None or dts is not None:
                            writer.writerow([packet_count, f"0x{pid:04X}", pts, dts])

            packet_count += 1

    print(f"提取完成，结果保存至: {output_csv}")

def parse_timestamp(data):
    """解析 33 位时间戳 (MPEG-2 格式)"""
    # 格式: 4bits(flag), 3bits, 1bit(marker), 15bits, 1bit(marker), 15bits, 1bit(marker)
    val = ((data[0] & 0x0E) << 29) | \
          (data[1] << 22) | \
          ((data[2] & 0xFE) << 14) | \
          (data[3] << 7) | \
          ((data[4] & 0xFE) >> 1)
    return val

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ts_raw_extractor.py <file.ts>")
    else:
        parse_ts_file(sys.argv[1], "output_ts_data.csv")