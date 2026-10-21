import matplotlib.pyplot as plt

sample_rate=96000

x_min=0
x_max = int((2**32)*1.5)
step = (x_max-x_min)//1000 # 使用整数除法
x = list(range(x_min, x_max, step))
yv = [xi & 0xFFFFFFFF for xi in x]
ya = [(xi & 0xFFFFFFFF) / 90000.0 * sample_rate for xi in x]
ya = [int(yi) & 0xFFFFFFFF for yi in ya]
ya2 = [int(yi / sample_rate * 90000.0) for yi in ya]
yv2 = yv

plt.figure(figsize=(12, 6))
plt.subplot(1, 2, 1)
plt.plot(x, yv, label='video')
plt.plot(x, ya, label='audio', alpha=0.7)
plt.axhline(y=2**32, color='purple', linestyle='--', label='y = 2^32')
plt.axvline(x=2**32, color='purple', linestyle='--', label='x = 2^32')
plt.title('sent rtp header pts')
plt.xlabel('64bit 90k pts')
plt.ylabel('rtp pts')
plt.legend()

plt.subplot(1, 2, 2)
plt.plot(x, yv2, label='video')
plt.plot(x, ya2, label='audio', alpha=0.7)
plt.axhline(y=2**32, color='purple', linestyle='--', label='y = 2^32')
plt.axvline(x=2**32, color='purple', linestyle='--', label='x = 2^32')
plt.title('rtp recv parsed pts')
plt.xlabel('64bit 90k pts')
plt.ylabel('rtp pts')
plt.legend()

plt.tight_layout()
plt.show()