#!/usr/bin/env python3
import argparse
import os
import sys

"""
在二进制层面拆分交织（Interleaved）PCM 文件
"""

def pcm_channel_split(input_file: str, channels: int, sample_bytes: int):
    if not os.path.isfile(input_file):
        print(f"错误: 找不到输入文件 '{input_file}'", file=sys.stderr)
        sys.exit(1)

    frame_size = channels * sample_bytes
    file_base, file_ext = os.path.splitext(input_file)
    chunk_frames = 8192
    read_buffer_size = frame_size * chunk_frames

    # 打开所有输出文件的句柄
    out_files = []
    try:
        for i in range(channels):
            out_name = f"{file_base}_ch{i}.pcm"
            out_files.append(open(out_name, "wb"))
        
        print(f"参数配置: {channels} 通道 | 单采样点 {sample_bytes} 字节 | 帧大小 {frame_size} 字节")

        total_bytes = 0
        with open(input_file, "rb") as f_in:
            while True:
                chunk = f_in.read(read_buffer_size)
                if not chunk:
                    break
                
                # 丢弃末尾不满足一个完整 Frame 的残缺字节
                valid_bytes = (len(chunk) // frame_size) * frame_size
                if valid_bytes == 0:
                    break

                # 提取当前 chunk 中各个通道的数据流
                for ch in range(channels):
                    # 使用切片直接按通道提取当前块中该通道的所有字节
                    # 开始位置: ch * sample_bytes
                    # 结束位置: valid_bytes
                    # 步长: frame_size (跨过一整帧)
                    ch_data = bytearray()
                    for frame_start in range(0, valid_bytes, frame_size):
                        ch_start = frame_start + ch * sample_bytes
                        ch_data.extend(chunk[ch_start : ch_start + sample_bytes])
                    
                    out_files[ch].write(ch_data)

                total_bytes += valid_bytes

        print(f"拆分完成！共处理 {total_bytes} 字节，生成 {channels} 个单通道文件。")

    except Exception as e:
        print(f"处理过程中发生错误: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for fp in out_files:
            fp.close()

def main():
    parser = argparse.ArgumentParser(
        description="多通道交织 PCM 文件拆分工具 (Interleaved PCM Splitter)"
    )
    
    parser.add_argument("-i", "--input", required=True, type=str, help="输入的 PCM 文件路径")
    parser.add_argument("-c", "--channels", required=True, type=int, help="声道数量（例如 5.1 声道传 6）")
    parser.add_argument("-b", "--sample-bytes", required=True, type=int, choices=[1, 2, 3, 4], help="每个采样点的字节数（如 s16le 传 2，s32le/f32le 传 4）")

    args = parser.parse_args()

    pcm_channel_split(
        input_file=args.input,
        channels=args.channels,
        sample_bytes=args.sample_bytes
    )

if __name__ == "__main__":
    main()