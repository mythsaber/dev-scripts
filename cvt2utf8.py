import os
import codecs

gErrArray = []

def convert(fileName, filePath, out_enc="utf-8"):
    try:
        content = codecs.open(filePath, 'rb').read()
        # 直接设置GB18030编码节省时间
        source_encoding = 'GB2312'
        print("{0:50}{1}".format(fileName, source_encoding))
        if source_encoding != None:
            if source_encoding == out_enc:
                return
            content = content.decode(source_encoding).encode(out_enc)
            codecs.open(filePath, 'wb').write(content)
        else:
            gErrArray.append("can not recgonize file encoding %s" % filePath)
    except Exception as err:
        gErrArray.append("%s:%s" % (filePath, err))

def show_files(base_path):
    """
    遍历当前目录所有py文件及文件夹
    :param path:
    :param all_files:
    :return:
    """
    file_list = os.listdir(base_path)
    # 准备循环判断每个元素是否是文件夹还是文件，是文件的话，把名称传入list，是文件夹的话，递归
    for file in file_list:
        # 利用os.path.join()方法取得路径全名，并存入cur_path变量，否则每次只能遍历一层目录
        cur_path = os.path.join(base_path, file)
        # 判断是否是文件夹
        if os.path.isdir(cur_path):
            show_files(cur_path)
        else:
            suffix = os.path.splitext(file)[1]
            if suffix == '.h' or suffix == '.c' or suffix == '.cpp' or suffix == '.hpp' or suffix == '.bat' or suffix == '.java' or suffix == '.txt':
                convert(file, cur_path)

def main():
    #explore(os.getcwd())
    filePath = input("请输入要转换编码的文件夹路径: \n")
    print("\r\n===============================================================")
    print("{0:50}{1}".format('fileName', 'fileEncoding'))
    print("===============================================================")
    show_files(filePath)
    print('\r\n---------错误统计------------')
    for index, item in enumerate(gErrArray):
        print(item)
    print('\r\n共%d个错误！' % (len(gErrArray)))
    if (len(gErrArray) > 0):
        print("请检查错误文件手动修改编码")
    print('\r\n-----------------------------')
 
if __name__ == "__main__":
    main()