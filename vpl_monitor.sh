#!/bin/bash

# 日志文件名定义
LOG1="vpl_monitor_sg_monitor_mem.log"
LOG2="vpl_monitor_i915_gem_objects.log"
LOG3="vpl_monitor_xpu-smi.log"
LOG4="vpl_monitor_proc_meminfo.log"
LOG5="vpl_monitor_free.log"

# PID 保存文件
SCRIPT_DIR=$(readlink -f "$(dirname "$0")")
cd "${SCRIPT_DIR}"
PID_FILE="${SCRIPT_DIR}/intel_media_sdk_monitor_pid.tmp"

# 操作系统检测
get_os_version() {
    local os_release_file="/etc/os-release"
    if [ ! -r "${os_release_file}" ]; then
        echo "[ERROR] can not read ${os_release_file}"
        exit 1
    fi

    if grep -q "Ubuntu" "${os_release_file}"; then
        echo "ubuntu"
    elif grep -q "Kylin" "${os_release_file}"; then
        echo "kylin"
    elif grep -q "CentOS" "${os_release_file}"; then
        echo "centos"
    else
        echo "unknown"
    fi
}

# 硬件环境检测
get_hardware_env() {
    # 检查 vainfo 命令是否可用
    if ! command -v vainfo &> /dev/null; then
        echo "[ERROR] vainfo 命令不可用或未安装！" >&2
        exit 1
    fi

    # 获取 vainfo 输出
    local vainfo_out
    vainfo_out=$(vainfo 2>&1)
    local vainfo_ret=$?
    if [ $vainfo_ret -ne 0 ]; then
        echo "[ERROR] vainfo 执行失败，请检查 VA-API 环境！" >&2
        exit 1
    fi

    # 判断是否为 SG1
    if echo "$vainfo_out" | grep -q "SG1"; then
        echo "SG1"
        return 0
    fi

    local lspci_vga
    lspci_vga=$(lspci | grep -i "VGA")

    local dg1_count=0
    local igpu_count=0

    # 统计 DG1 数量
    dg1_count=$(echo "$lspci_vga" | grep -c "DG1")

    # 统计 核显 数量
    igpu_count=$(echo "$lspci_vga" | grep -E -c "HD Graphics|UHD Graphics|Iris Xe Graphics|Integrated Graphics Controller")

    # 识别硬件组合
    if [ "$dg1_count" -eq 4 ]; then
        echo "4_DG1"
    elif [ "$dg1_count" -eq 2 ] && [ "$igpu_count" -ge 1 ]; then
        echo "2_DG1_1_IGPU"
    elif [ "$igpu_count" -eq 1 ] && [ "$dg1_count" -eq 0 ]; then
        echo "ONLY_1_IGPU"
    else
        echo "UNKNOWN_HW"
    fi
}

# xpu-smi 可用性检查
check_xpu_smi() {
    if ! command -v xpu-smi &> /dev/null; then
        echo "[ERROR] xpu-smi 命令不存在或未在 PATH 中找到！" >&2
        exit 1
    fi

    # 尝试运行 xpu-smi -h 确认驱动/服务正常
    if ! xpu-smi -h &> /dev/null; then
        echo "[ERROR] xpu-smi 命令无法正常执行！" >&2
        exit 1
    fi
}

# 停止监测逻辑 (精准杀死记录的 PID 及其子进程)
stop_monitoring() {
    echo "stopping msdk monitoring processes..."

    if [ ! -f "$PID_FILE" ]; then
        echo "[WARNING] PID file ($PID_FILE) not found. is monitoring running?"
        return 0
    fi

    # 逐行读取 PID 并处理
    while IFS= read -r pid; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "killing PID $pid and its child processes..."
            
            # 强杀由该 shell 产生的子进程 (如 cat, free 等)
            pkill -9 -P "$pid" 2>/dev/null
            
            # 直接强杀主进程 (SIGKILL)
            kill -9 "$pid" 2>/dev/null
        fi
    done < "$PID_FILE"

    # 清理 PID 文件
    rm -f "$PID_FILE"
    echo "stop monitoring successfully [OK]"
}

# 清理上次遗留的日志
clean_logs() {
    rm -f "$LOG1" "$LOG2" "$LOG3" "$LOG4" "$LOG5"
}

# 启动监测逻辑
start_monitoring() {
    # 防重复启动检查
    if [ -f "$PID_FILE" ]; then
        echo "[ERROR] monitoring is already running (PID file $PID_FILE exists). stop it first!"
        exit 1
    fi

    clean_logs

    local os
    local hw
    os=$(get_os_version)
    hw=$(get_hardware_env)

    if [ "$os" = "centos" ] && [ "$hw" = "SG1" ]; then
        # (a) centos + sg1 ---> 在后台执行命令1
        echo "starting monitoring for Environment: CentOS + SG1"
        nohup bash -c 'while true; do date; ./sg_monitor -n 1 | grep "GPU MEM Usage"; sleep 10; done' >> "$LOG1" 2>&1 &
        echo $! >> "$PID_FILE"

    elif [ "$os" = "centos" ] && [ "$hw" = "4_DG1" ]; then
        # (b) centos + 4个dg1 ---> 报错，暂不支持
        echo "[ERROR] CentOS + 4个DG1 环境暂不支持！"
        exit 1

    elif [ "$os" = "ubuntu" ] && [ "$hw" = "2_DG1_1_IGPU" ]; then
        # (c) ubuntu + 2个DG1 + 1个核显 ---> 在后台执行命令3、4、5
        echo "starting monitoring for Environment: Ubuntu + 2*DG1 + iGPU"
        
        check_xpu_smi

        nohup xpu-smi dump -d 0,1,2 -m 0,2,3,5,18 -i 30 >> "$LOG3" 2>&1 &
        echo $! >> "$PID_FILE"

        nohup bash -c 'while true; do date; cat /proc/meminfo | head -30; sleep 120; done' >> "$LOG4" 2>&1 &
        echo $! >> "$PID_FILE"

        nohup bash -c 'while true; do date; free -h; sleep 30; done' >> "$LOG5" 2>&1 &
        echo $! >> "$PID_FILE"

    elif [ "$hw" = "ONLY_1_IGPU" ]; then
        # (d) 仅一个核显 ---> 在后台执行命令2、4、5
        echo "starting monitoring for Environment: Only iGPU"

        check_xpu_smi

        nohup xpu-smi dump -d 0 -m 0,2,3,5,18 -i 30 >> "$LOG3" 2>&1 &
        echo $! >> "$PID_FILE"

        nohup bash -c 'while true; do date; cat /sys/kernel/debug/dri/0/i915_gem_objects; sleep 30; done' >> "$LOG2" 2>&1 &
        echo $! >> "$PID_FILE"

        nohup bash -c 'while true; do date; cat /proc/meminfo | head -30; sleep 120; done' >> "$LOG4" 2>&1 &
        echo $! >> "$PID_FILE"

        nohup bash -c 'while true; do date; free -h; sleep 30; done' >> "$LOG5" 2>&1 &
        echo $! >> "$PID_FILE"

    else
        # (e) 其它环境，直接报错
        echo "[ERROR] 无法识别的环境"
        exit 1
    fi

    echo "monitor started successfully!"
}

# ==========================================
# 主入口
# ==========================================
case "$1" in
    start)
        start_monitoring
        ;;
    stop)
        stop_monitoring
        ;;
    *)
        echo "usage: $0 {start|stop}"
        exit 1
        ;;
esac

cd - > /dev/null