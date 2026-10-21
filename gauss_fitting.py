import numpy as np
import matplotlib.pyplot as plt
from scipy.optimize import curve_fit

# 定义高斯函数
def gaussian_distribution(x,sigma,scale):
    """
    计算高斯分布的概率密度函数
    :param x: 自变量
    :param mu: 平均值，默认为0
    :param sigma: 标准差，默认为1
    :return: 概率密度函数值
    """
    coefficient = 1 / (sigma * np.sqrt(2 * np.pi))  # 计算系数
    coefficient = coefficient*scale
    exponent = np.exp(-0.5 * ((x) / sigma) ** 2)  # 计算指数部分
    return coefficient * exponent  # 返回高斯分布值


# 生成数据
#x = np.linspace(-5, 5, 100)
#y = gaussian_distribution(x, 2)
x = [-3, -1, 1, 3]
y = [16, 112, 112, 16]

# 进行拟合
popt, pcov = curve_fit(gaussian_distribution, x, y)

# 输出拟合参数
print(popt)  #a 

# 绘制原始数据和拟合结果
plt.plot(x, y, 'b-', label='data')
plt.plot(x, gaussian_distribution(x, *popt), 'r-', label='fit')
print(gaussian_distribution(x, *popt))

plt.legend()
plt.show()