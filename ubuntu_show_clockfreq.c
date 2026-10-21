#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <cpuid.h>

// x86/x86_64架构读取TSC（时间戳计数器）
static inline uint64_t read_tsc(void) {
    uint32_t lo, hi;
    // 序列化指令，确保TSC读取的准确性
    __asm__ __volatile__ (
        "cpuid\n"
        "rdtsc\n"
        "mov %%edx, %0\n"
        "mov %%eax, %1\n"
        : "=r" (hi), "=r" (lo)
        :
        : "%rax", "%rbx", "%rcx", "%rdx"
    );
    return ((uint64_t)hi << 32) | lo;
}

// 估算TSC的频率（提前校准）
static uint64_t get_tsc_freq(void) {
    struct timespec t0, t1;
    uint64_t c0, c1;

    clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
    c0 = read_tsc();
    // 短时间忙等，减少sleep的误差
    for (volatile int i = 0; i < 100000000; i++);
    clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
    c1 = read_tsc();

    double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    uint64_t dc = c1 - c0;
    return (uint64_t)(dc / dt);
}

int main(void) {
    // 校准TSC频率（x86替代ARM的cntfrq_el0）
    uint64_t tsc_freq = get_tsc_freq();
    printf("TSC Frequency (calibrated): %llu Hz\n\n", (unsigned long long)tsc_freq);

    double total_rate = 0;
    int i = 0;
    for (i = 0; i < 10; ++i) {
        struct timespec t0, t1;
        uint64_t c0, c1;

        clock_gettime(CLOCK_MONOTONIC, &t0);
        c0 = read_tsc();
        sleep(5);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        c1 = read_tsc();

        // 计算真实流逝时间
        double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        // 计算TSC计数器差值
        uint64_t dc = c1 - c0;
        // 实测TSC频率
        double measured_hz = dc / dt;
        // 计算频率比值（替代原ARM的rate逻辑）
        double rate = measured_hz / (double)tsc_freq;
        total_rate += rate;

        printf("Elapsed real time: %.9f s\n", dt);
        printf("TSC delta: %llu ticks -> measured frequency: %.3f Hz\n", 
               (unsigned long long)dc, measured_hz);
        printf("rate: %.6f\n\n", rate);
    }

    printf("average rate=%.6f\n", total_rate / i);
    return 0;
}