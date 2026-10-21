import csv
import numpy as np
import matplotlib.pyplot as plt

# ========== 用户可修改参数 ==========
start_row = 12*60*60*25      # 起始数据行索引（从0开始，即跳过表头后的第1条数据）
end_row = -1       # 结束数据行索引，-1表示到文件末尾
# ===================================

# 读取 CSV 文件（第一行为表头；第一列为系统时间单位ns，第2列为pts单位90KHZ）
sys_ns_list = []
pts_90k_list = []

with open('sdiin_clockdrift_INPUT_0_bd18aa40-a645-44df-942d-5dbb177f0171_20260324_185301_376642897.csv', 'r') as f:
    reader = csv.reader(f)
    header = next(reader)   # 跳过表头
    row_idx = 0
    for row in reader:
        if row_idx < start_row:
            row_idx += 1
            continue
        if end_row != -1 and row_idx > end_row:
            break
        if len(row) >= 2:
            sys_ns_list.append(float(row[0]))
            pts_90k_list.append(float(row[1]))
        row_idx += 1

# 检查是否读取到数据
if len(sys_ns_list) == 0:
    print(f"未读取到数据，请检查 start_row={start_row} 和 end_row={end_row} 是否正确。")
    exit()

print(f"已读取 {len(sys_ns_list)} 行数据（数据行范围：{start_row} 至 {end_row if end_row != -1 else '末尾'}）")

# 转换为 numpy 数组，便于向量化计算
sys_ns = np.array(sys_ns_list)
pts_90k = np.array(pts_90k_list)

# 系统时钟归一化：以第一个系统时钟为 0
sys_ns = sys_ns - sys_ns[0]

# 转换为毫秒
sys_ms = sys_ns / 1e6           # 纳秒 → 毫秒
pts_ms = pts_90k / 90.0         # 90kHz tick → 毫秒

# 计算原始偏移（毫秒）
delta_ms = pts_ms - sys_ms

# 相对偏移（消除固定初始偏差）
delta_rel_ms = delta_ms - delta_ms[0]

# 绘图
plt.rcParams['font.sans-serif']=['SimHei']  #用来正常显示中文标签
plt.rcParams['axes.unicode_minus']=False #用来正常显示负号
plt.figure(figsize=(10, 5))
plt.plot(sys_ms, delta_rel_ms, marker='.', linestyle='-', markersize=2, linewidth=0.8)
plt.xlabel('系统时间 (毫秒)')
plt.ylabel('相对偏移 (毫秒)')
plt.title('PTS 与系统时钟的相对偏移随时间变化 (单位: 毫秒)')
plt.grid(True)
# plt.show()

# 5. 线性回归检测漂移（斜率单位：毫秒/毫秒）
coeffs = np.polyfit(sys_ms, delta_rel_ms, 1)
slope_ms_per_ms = coeffs[0]          # 毫秒/毫秒
intercept_ms = coeffs[1]

# 转换为更直观的漂移率：毫秒/秒
slope_ms_per_s = slope_ms_per_ms * 1000.0

print(f'线性回归斜率: {slope_ms_per_ms:.6e} 毫秒/毫秒')
print(f'漂移率: {slope_ms_per_s:.6f} 毫秒/秒')
print(f'截距: {intercept_ms:.6f} 毫秒')

# 可选：计算偏移的标准差（抖动大小）
print(f'相对偏移标准差: {np.std(delta_rel_ms):.6f} 毫秒')