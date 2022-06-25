进程内存操作工具

介绍

一个使用C实现的Linux/Android进程内存读写工具

依赖

libc

构建

cc main.c -o memctl

使用

./memctl

命令:
exit					退出
open pid				打开进程
info					格式化打印已经打开的进程信息
close					清理进程
dump start len prefix	把指定内存区域输出到文件中
print address len		读取内存区域并使用16进制格式打印
write address hex		往进程的内存区域写入数据

输出文件名:
prefix_pid_start_end.mem

开发计划:

v 已经实现
x 未实现

v 实现一个类似 dos debug 的界面
x 内置 lisp 解释器用于编写脚本