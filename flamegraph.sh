#!/bin/bash

# 检查是否传入了 PID 参数 ($1 代表第一个参数)
if [ -z "$1" ]; then
    echo "错误：未指定进程 PID！"
    echo "用法: $0 <PID>"
    exit 1
fi

TARGET_PID=$1

echo "开始针对进程 PID: ${TARGET_PID} 进行 30 秒的 perf 采样..."
perf record -F 99 -p "${TARGET_PID}" -g -- sleep 30
echo "采样完成，开始生成火焰图..."
perf script -i perf.data > out.perf
/home/software/FlameGraph/stackcollapse-perf.pl out.perf > out.floded
/home/software/FlameGraph/flamegraph.pl out.floded > cp.svg

echo "火焰图生成完成：cp.svg"
