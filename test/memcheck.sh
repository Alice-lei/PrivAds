#!/bin/bash
# 设置变量'target'的默认值为 'main'
target=main

# 检查是否传递了参数。如果有则将第一个传递的参数赋值给'target'
if [ $# -ne 0 ]
  then
    target=$1
fi

# 找到二进制文件的完整路径并将其赋值给 'target' 变量
target=$(readlink -f ../build/bin/$target)

# 运行valgrind来检查内存泄漏，并将报告输出到'./memcheck_report.log'
valgrind --tool=memcheck --leak-check=full --log-file=./memcheck_report.log $target
