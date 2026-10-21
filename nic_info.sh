#!/usr/bin/env bash

# 校验输入参数
if [ -z "$1" ]; then
    echo "错误: 请提供网卡名称！"
    echo "用法: $0 <网卡名称>  (例如: $0 eno1)"
    exit 1
fi

IFNAME="$1"
SYS_PATH="/sys/class/net/${IFNAME}"

# 校验网卡是否存在
if [ ! -d "${SYS_PATH}" ]; then
    echo "错误: 网卡 '${IFNAME}' 在系统中不存在！"
    exit 1
fi

echo "=================================================="
echo " 网卡综合信息查询: ${IFNAME}"
echo "=================================================="

# 获取 IPv4 地址
ip_addr=$(ip -4 addr show dev "${IFNAME}" 2>/dev/null | awk '/inet / {print $2}' | cut -d'/' -f1)
echo "IPv4 地址      : ${ip_addr:-未配置 IP / 接口Down} (ip a s ${IFNAME})"

# 获取 PCI BDF 地址 (lspci 使用的 Bus:Device.Function 参数)
pci_bdf=$(basename "$(readlink "${SYS_PATH}/device" 2>/dev/null)" 2>/dev/null)
if [ -n "${pci_bdf}" ] && [ -d "${SYS_PATH}/device" ]; then
    echo "PCI BDF 地址   : ${pci_bdf}  (ethtool -i ${IFNAME})"
else
    echo "PCI BDF 地址   : 虚拟网卡/非 PCI 设备"
    pci_bdf=""
fi

# 获取 NUMA 节点
numa_node=$(cat "${SYS_PATH}/device/numa_node" 2>/dev/null || echo "未知")
if [ "${numa_node}" = "-1" ]; then
    numa_node="0 (单 NUMA 节点/不受限)"
fi
echo "NUMA 节点      : ${numa_node} (lspci -vs ${pci_bdf})"

# 获取驱动信息
driver_name=$(ethtool -i "${IFNAME}" 2>/dev/null | awk '/^driver:/ {print $2}')
echo "使用的驱动     : ${driver_name:-未知} (ethtool -i ${IFNAME})"

# 获取 PCI 硬件型号 (如 Intel X710 等)
if [ -n "${pci_bdf}" ]; then
    model_info=$(lspci -s "${pci_bdf}" 2>/dev/null | cut -d':' -f3- | sed 's/^[ \t]*//')
else
    model_info="虚拟网卡/无 PCI 实体"
fi
echo "硬件型号       : ${model_info} (lspci -s ${IFNAME})"

# 输出 ethtool -T 时间戳能力
echo "--------------------------------------------------"
echo " 时间戳能力 (ethtool -T ${IFNAME}):"
echo "--------------------------------------------------"
ethtool -T "${IFNAME}" 2>/dev/null || echo "获取时间戳信息失败"

echo "=================================================="
