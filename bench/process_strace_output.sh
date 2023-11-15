#!/bin/bash

# 指定要搜索的文件
FILE_NAME="strace_output.txt"

# 指定要搜索的字符串
SEARCH_STRING="Type"

# 使用 grep 搜索字符串，再使用 wc -l 计算行数
COUNT=$(grep -o "$SEARCH_STRING" "$FILE_NAME" | wc -l)

echo "The string '$SEARCH_STRING' appeared $COUNT times in the file $FILE_NAME."
