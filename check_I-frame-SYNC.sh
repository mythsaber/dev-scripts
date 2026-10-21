#!/bin/bash
set -euo pipefail

# ===== 在这里填写要监听的 URL =====
urls=(
    "srt://192.165.56.81:8001"
    "srt://192.165.56.81:8002"
    "srt://192.165.56.81:8003"
)

# 注，bash数组语法：
# ${urls[@]}	数组的所有值
# ${!urls[@]}	数组的所有下标（! 取的是 key 而不是 value）	0 1 2
# ${#urls[@]}	数组的元素个数（# 是长度）
if [ "${#urls[@]}" -lt 2 ]; then
    echo "错误：请先在 urls 数组中配置至少 2 个 URL" >&2
    exit 1
fi

# 输出文件名：pkt_0.csv、pkt_1.csv、……
out_file=()
for i in "${!urls[@]}"; do
    out_file+=("pkt_${i}.csv")
done

pids=()

start_probe() {
    local i url csv
    for i in "${!urls[@]}"; do
        url="${urls[$i]}"
        csv="${out_file[$i]}"
        rm -f "$csv"
        # 用 exec 让后台进程直接变成 ffprobe，记录下来的 PID 就是 ffprobe 本身，便于精确结束
        # bash -c 的规则：bash -c '命令串' 名字 参数1 参数2 ... 中，'命令串' 之后的第一个词会成为子 shell 的 $0（这里用 _ 占位），后面依次是 $1、$2。
        # 所以子 shell 里第一句 csv=$1; url=$2 就把它们变成了子 shell 自己的变量，随后 $csv、$url 自然可用，全程不需要 export
        nohup bash -c 'csv=$1; url=$2; echo entry,pts,dts > "$csv"; exec ffprobe -v error -hide_banner -i "$url" -select_streams v:0 -of csv -show_entries "packet=pts,dts" >> "$csv"' _ "$csv" "$url" >/dev/null 2>&1 &
        pids+=("$!")
        echo "已启动：$url -> $csv"
    done
}

stop_probe() {
    local pid
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    # 等进程真正退出，确保 ffprobe 已把缓冲区内容刷入 CSV
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    pids=()

    echo
    echo "================ 采集停止，开始比对 ================"
    show_result
}

# 数据行数
data_rows() {
    local n
    n=$(wc -l < "$1")
    echo $n
}

# 两个文件中“完全相同”的行数（按 diff 对齐）
same_rows() {
    local n
    # GNU diff 把比较结果分成四类“行组”，每个选项用来覆盖该类行组的输出格式：
    # --unchanged-group-format='%='	两边完全相同的行，%= 表示把这些行原样输出
    # --old-group-format=''	只在第一个文件里有的行（被删除的），空字符串 = 不输出
    # --new-group-format=''	只在第二个文件里有的行（新增的），不输出
    # --changed-group-format=''	两边都有但内容不同的行（替换），不输出
    n=$(diff \
        --unchanged-group-format='%=' \
        --old-group-format='' \
        --new-group-format='' \
        --changed-group-format='' \
        "$1" "$2" | wc -l || true)
    echo $n
}

show_result() {
    local base="${out_file[0]}"
    if [ ! -f "$base" ]; then
        echo "未找到 $base，无法比对" >&2
        return 0
    fi

    local i csv
    # 逐个文件与第一个文件（基准）对比
    for i in "${!urls[@]}"; do
        if [ "$i" -eq 0 ]; then
            continue
        fi
        csv="${out_file[$i]}"
        if [ -f "$csv" ]; then
            show_pair "$base" "$csv"
        else
            echo "=======  $csv 文件不存在======="
        fi
    done
}

show_pair() {
    local a=$1 b=$2
    local rows_a rows_b
    rows_a=$(data_rows "$a")
    rows_b=$(data_rows "$b")

    echo
    echo "======= $a（$rows_a 行）  vs  $b（$rows_b 行） ======="

    # diff 的直接结果
    echo "[diff命令 结果]"
    local rc=0
    diff "$a" "$b" || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "完全一致"
    else
        echo "共有 $(same_rows "$a" "$b") 行一致"
    fi
}

# Ctrl+C / kill 时执行清理
trap 'stop_probe; exit 0' INT TERM

# 参数：compare_only 表示不采集，直接比对已有的 CSV 文件
case "${1:-}" in
    compare_only)
        show_result
        exit 0
        ;;
    "")
        ;;
    *)
        echo "用法: $0 [compare_only]" >&2
        echo "  （不带参数）     采集数据，Ctrl+C 停止后自动比对" >&2
        echo "  compare_only    不采集，直接比对已有的 CSV 文件" >&2
        exit 1
        ;;
esac

# 主入口：直接运行即启动
start_probe

while true; do
    sleep 3600 & # & 表示放到后台，$! 会立刻被赋值为这个 sleep 进程的 PID
    wait $! # 等待后台 sleep 进程结束。wait 是可被信号中断的。当脚本收到 SIGINT（Ctrl+C）或 SIGTERM 时，wait 会立刻返回（被信号打断），而不是傻等 1 小时
done
