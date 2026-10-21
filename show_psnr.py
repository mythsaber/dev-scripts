"""
功能：
使用ffmpeg -s 1920x1080 -pix_fmt yuv420p -i ./ref.yuv -s 1920x1080 -pix_fmt yuv420p -i ./cap.yuv -lavfi psnr="psnr.txt" -f null -
命令后，会生成一个.txt文件，内容如下：
n:1 mse_avg:0.82 mse_y:1.02 mse_u:0.36 mse_v:0.45 psnr_avg:49.00 psnr_y:48.03 psnr_u:52.54 psnr_v:51.56 
n:2 mse_avg:1.00 mse_y:1.25 mse_u:0.43 mse_v:0.56 psnr_avg:48.13 psnr_y:47.15 psnr_u:51.82 psnr_v:50.62 
n:3 mse_avg:1.04 mse_y:1.29 mse_u:0.45 mse_v:0.61 psnr_avg:47.97 psnr_y:47.01 psnr_u:51.65 psnr_v:50.30 
……
该脚本用于读取ffmpeg的输出内容，绘制出psnr的点线图
"""
import matplotlib.pyplot as plt
import re

def plot_psnr(file_path):
    frames = []
    psnr_avg = []
    psnr_y = []

    # 正则表达式提取数据
    pattern = re.compile(r"n:(\d+).*psnr_avg:(\d+\.\d+).*psnr_y:(\d+\.\d+)")

    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    frames.append(int(match.group(1)))
                    psnr_avg.append(float(match.group(2)))
                    psnr_y.append(float(match.group(3)))
    except FileNotFoundError:
        print(f"错误：找不到文件 {file_path}")
        return

    # 开始绘图
    plt.figure(figsize=(12, 6))
    
    # 绘制全局平均 PSNR
    plt.plot(frames, psnr_avg, label='PSNR Average', color='blue', marker='o', markersize=4, linewidth=1.5)
    # 绘制亮度分量 PSNR (通常最影响视觉质量)
    plt.plot(frames, psnr_y, label='PSNR Y (Luma)', color='red', linestyle='--', alpha=0.7)

    # 图表装饰
    plt.title('Video Quality Analysis (PSNR)', fontsize=14)
    plt.xlabel('Frame Number', fontsize=12)
    plt.ylabel('PSNR (dB)', fontsize=12)
    plt.grid(True, which='both', linestyle='--', alpha=0.5)
    plt.legend()
    
    # 设置 y 轴范围，让波动更明显（或根据需要固定范围）
    if psnr_avg:
        plt.ylim(min(psnr_avg) - 1, max(psnr_y) + 1)

    plt.tight_layout()
    plt.show()

# 使用说明：将 'psnr.txt' 替换为你的文件名
if __name__ == "__main__":
    plot_psnr('psnr.txt')