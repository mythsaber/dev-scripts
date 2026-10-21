#!/bin/bash

target="$1"

# 判断第一个参数是否为有效目录或文件
if [ ! -d "$target" ] && [ ! -f "$target" ]; then
    echo "Error: $target is not a valid directory or file."
    exit 1
fi

# 循环处理每个文件和目录
while IFS= read -r -d '' file; do
    # 获取文件或目录的所有者对文件的访问权限
    owner_permissions=$(stat -c "%A" "$file" | cut -c 2-4)
    
    # 将文件或目录的权限修改为所有用户与属主权限一致
    chmod u=$owner_permissions,g=$owner_permissions,o=$owner_permissions "$file"
done < <(find "$target" -print0)
