#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from __future__ import print_function
import sys
import zipfile
import io
import os

def inspect_nested_zip(path_chain):
    if not path_chain:
        print(u"错误：未提供任何压缩包路径。")
        return

    outer_file_path = path_chain[0]
    print(u"[*] 正在打开最外层压缩包: {0}".format(outer_file_path))

    try:
        # 打开最外层文件
        file_obj = open(outer_file_path, 'rb')
        current_zip = zipfile.ZipFile(file_obj)

        # 逐层深入里层的 zip 包
        for i in range(1, len(path_chain)):
            target_sub_zip = path_chain[i]
            print(u"[*] 正在穿透到第 {0} 层嵌套: {1}".format(i, target_sub_zip))

            # 在当前层查找目标 zip（文件名统一按 UTF-8/ASCII 处理）
            if target_sub_zip not in current_zip.namelist():
                print(u"错误：在当前压缩包中未找到路径或文件 '{0}'".format(target_sub_zip))
                current_zip.close()
                file_obj.close()
                return

            # 将里层的 zip 读取到内存缓冲区
            data = current_zip.read(target_sub_zip)

            # 关闭上一层的资源
            current_zip.close()
            file_obj.close()

            # 用内存对象接管并包装成新的 ZipFile
            file_obj = io.BytesIO(data)
            current_zip = zipfile.ZipFile(file_obj)

        # 到达最内层的 zip 包，直接打印其文件列表
        innermost_name = path_chain[-1]
        print(u"\n================ 成功到达最内层 [{0}] ================".format(innermost_name))
        current_zip.printdir()
        print(u"================================================================")

        # 清理最后的资源
        current_zip.close()
        file_obj.close()

    except Exception as e:
        print(u"执行过程中发生异常: {0}".format(e))

if __name__ == '__main__':
    # 参数检查
    if len(sys.argv) < 2:
        script_name = os.path.basename(sys.argv[0])
        print(u"使用方法:")
        print(u"  单层: python2 {0} outer.zip".format(script_name))
        print(u"  双层: python2 {0} outer.zip inner.zip".format(script_name))
        print(u"  多层: python2 {0} outer.zip sub/inner.zip deep.zip ...".format(script_name))
        print(u"  多层: python2 {0} xStream2050_v1.10.520.122655_KylinV10_aarch64_2026-08-10-15-44-47.zip xStream2050_v1.10.520.122655_KylinV10_aarch64_2026-08-10-15-44-47/xStream2050_v1.10.520.122655_KylinV10_aarch64.zip".format(script_name))
        sys.exit(1)

    # 适配 Python 2 命令行参数编码（防止传入中文路径时乱码）
    args = []
    fs_enc = sys.getfilesystemencoding() or 'utf-8'
    for arg in sys.argv[1:]:
        try:
            arg = arg.decode(fs_enc)   # Python2 成功：bytes -> unicode
        except:                        # Python3 抛 AttributeError: 'str' 没有 decode
            pass                       # 吞掉，arg 保持原样
        args.append(arg)

    inspect_nested_zip(args)
