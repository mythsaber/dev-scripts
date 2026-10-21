#!/usr/bin/env python3
"""
功能：
监控 MediaTransform 日志，每分钟(CHECK_INTERVAL)检查最近10秒(HANG_SECONDS)内的日志，
检测是否有源连续10秒每秒丢帧数 ≥20(MIN_DROP_FRAMES_FOR_HANG)，若是则杀死进程。
日志按小时分割，路径格式：
/usr/sbin/sumavision/log/xStream2050s/xStream2050_0/MediaTransform/sys/YYYY-MM-DD/YYYY-MM-DD-HH.log

用法：
放到一个单独的目录下，root用户
执行命令后台运行：nohup python3 -u check_block.py &
查看进程用ps -ef | grep python3，进程名叫python3 -u check_block.py
会生成一个nohup.out的文件，里边是脚本记录的日志
"""

import os
import sys
import re
import time
import subprocess
from datetime import datetime

# ========== 可配置参数 ==========
BASE_LOG_DIR = "/usr/sbin/sumavision/log/xStream2050s/xStream2050_0/MediaTransform/sys"
#BASE_LOG_DIR = "/home/zcj/mediatransform/Programs/MediaTransform/branches/v1.10/build/linux/ubuntu22.04/x64/Server/log/xStream2050s/xStream2050/MediaTransform/sys"
MIN_DROP_FRAMES_FOR_HANG = 23             # 丢帧数阈值（25fps 源阻死时约25）
HANG_SECONDS = 10                          # 需要连续多少秒触发
CHECK_INTERVAL = 30                         # 检查间隔（秒）
COOLDOWN_SECONDS = 600                   # 触发 kill 后的冷却时间（秒），避免短时间内反复执行
MAX_TAIL_LINES = 5000                      # 每次 tail 读取的最大行数（需确保覆盖最近HANG_SECONDS秒）
# ================================

def get_current_log_path(now):
    """根据当前时间返回对应的日志文件路径"""
    date_dir = now.strftime("%Y-%m-%d")
    hour_file = now.strftime("%Y-%m-%d-%H.log")
    return os.path.join(BASE_LOG_DIR, date_dir, hour_file)

def is_cross_hour_boundary(now, seconds_back):
    """判断从 now-seconds_back 到 now 是否跨小时"""
    now_ts = now.timestamp()
    start_ts = now_ts - seconds_back
    start_hour = datetime.fromtimestamp(start_ts).hour
    end_hour = now.hour
    return start_hour != end_hour

def extract_timestamp(line):
    """
    从日志行中提取时间戳（YYYY-MM-DD HH:MM:SS）
    日志格式示例：[2079919] 2026-03-02 16:44:42 807: ...
    返回时间戳字符串或 None
    """
    # 找到第一个 ']' 的位置
    pos = line.find(']')
    if pos == -1:
        return None
    # 跳过 ']' 后的空格
    start = pos + 1
    while start < len(line) and line[start] == ' ':
        start += 1
    # 时间戳固定为19个字符：YYYY-MM-DD HH:MM:SS
    if start + 19 > len(line):
        return None
    ts_candidate = line[start:start+19]
    # 简单验证格式（可选）
    if len(ts_candidate) == 19 and ts_candidate[4] == '-' and ts_candidate[7] == '-' and ts_candidate[13] == ':' and ts_candidate[16] == ':':
        return ts_candidate
    else:
        return None

def get_recent_log_lines(log_path, now, seconds_back=HANG_SECONDS, max_lines=MAX_TAIL_LINES):
    """
    从指定日志文件中获取最近 seconds_back 秒内的所有行。
    返回列表，每个元素为 (时间戳, 原始行)
    如果文件不存在，返回空列表。
    """
    if not os.path.isfile(log_path):
        print(f"[{now}] 日志文件 {log_path} 不存在", file=sys.stderr)
        return []

    cutoff = now.timestamp() - seconds_back

    try:
        # 使用 tail -n 读取最后 max_lines 行
        output = subprocess.check_output(
            ["tail", "-n", str(max_lines), log_path],
            universal_newlines=True,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError as e:
        print(f"[{now}] 执行 tail 失败: {e}", file=sys.stderr)
        return []
    except FileNotFoundError:
        print(f"[{now}] tail 命令不存在", file=sys.stderr)
        sys.exit(1)

    lines = output.splitlines()
    recent = []

    for line in lines:
        time_str = extract_timestamp(line)
        if not time_str:
            continue
        try:
            dt = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
            ts = dt.timestamp()
            if ts >= cutoff:
                recent.append((ts, line))
        except ValueError:
            # 时间格式异常，忽略该行
            continue

    return recent

def check_hang(lines):
    """
    从最近日志行中检测阻死。
    返回 (是否阻死, 触发阻死的源ID)
    判定条件（针对每个源）：
      1. 在检测窗口内，没有出现任何一条丢帧数低于 MIN_DROP_FRAMES_FOR_HANG 的日志；
      2. 丢帧日志出现的不同秒数 ≥ ceil(HANG_SECONDS/2) （即至少每2秒一次）；
      3. 总丢帧数 ≥ MIN_DROP_FRAMES_FOR_HANG * HANG_SECONDS （平均每秒丢帧数不低于阈值）。
    """
    pattern = re.compile(r'Module (.*?) lose (\d+) frames before plugin \[es_analyse:.*?\]')
    source_data = {}  # 结构：{源ID: {"total": 总丢帧, "seconds": set, "has_low": bool}}

    for ts, line in lines:
        m = pattern.search(line)
        if not m:
            continue
        source = m.group(1).strip()
        drop = int(m.group(2))
        second = int(ts)

        # 初始化源的数据结构
        if source not in source_data:
            source_data[source] = {"total": 0, "seconds": set(), "has_low": False}

        if drop >= MIN_DROP_FRAMES_FOR_HANG:
            # 高丢帧日志，计入统计
            source_data[source]["total"] += drop
            source_data[source]["seconds"].add(second)
        else:
            # 低丢帧日志，标记该源不可能是阻死
            source_data[source]["has_low"] = True

    # 计算所需的最小出现秒数和总丢帧数
    min_required_seconds = (HANG_SECONDS + 1) // 2  # 向上取整
    min_required_total = MIN_DROP_FRAMES_FOR_HANG * HANG_SECONDS

    for source, data in source_data.items():
        if data["has_low"]:
            # 一旦出现低丢帧日志，本次检测排除该源
            continue
        if len(data["seconds"]) >= min_required_seconds and data["total"] >= min_required_total:
            return True, source

    return False, None

def main():
    print(f"[{datetime.now()}] 开始监控，日志目录：{BASE_LOG_DIR}，检查间隔：{CHECK_INTERVAL}秒")
    print(f"[{datetime.now()}] 触发 kill 后将冷却 {COOLDOWN_SECONDS} 秒")
    print(f"[{datetime.now()}] 检测窗口 {HANG_SECONDS} 秒，需要出现丢帧秒数 ≥{(HANG_SECONDS+1)//2}，总丢帧 ≥{MIN_DROP_FRAMES_FOR_HANG*HANG_SECONDS}")

    while True:
        now = datetime.now()

        # 如果时间窗口跨小时，跳过本次检查
        if is_cross_hour_boundary(now, HANG_SECONDS):
            print(f"[{now}] 时间窗口跨小时，跳过本次检查")
            time.sleep(CHECK_INTERVAL)
            continue

        # 获取当前小时对应的日志文件
        log_path = get_current_log_path(now)

        # 获取最近几秒的日志行
        lines = get_recent_log_lines(log_path, now, seconds_back=HANG_SECONDS + 2, max_lines=MAX_TAIL_LINES)

        if not lines:
            print(f"[{now}] 最近 {HANG_SECONDS} 秒内无日志（或文件为空）")

        hang_detected, source = check_hang(lines)

        if hang_detected:
            print(f"[{now}] 检测到源 [{source}] 在最近 {HANG_SECONDS} 秒内出现足够密集的丢帧，执行 killall MediaTransform")
            os.system("killall MediaTransform")
            print(f"[{datetime.now()}] 已执行 kill，等待 {COOLDOWN_SECONDS} 秒后继续监控")
            time.sleep(COOLDOWN_SECONDS)  # 冷却期
        else:
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()