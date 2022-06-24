进程内存操作工具

介绍

一个使用C实现的Linux/Android进程内存读写工具

依赖

libc

构建

cc main.c -o memctl

使用

v 为已经实现
x 为未实现

命令:
v exit	退出
v quit	退出
v open	pid	打开进程
v info	读取 /proc/pid/maps 并格式化打印
v close	清理进程
v dumpall	prefix	将进程的所有内存区域输出到文件 "prefix_pid_start_end.mem" 文件中
v dump	start	end	prefix	把start到end之间的内存输出到 "prefix_pid_start_end.mem" 文件中
x write	address	data	往进程的内存地址address写入data
x print address	length	读取内存区域，使用16进制格式打印
x search	address	length	data	在内存区域中搜索内容

开发计划:

x 内置 lisp 解释器用于编写脚本
x 分离为客户端/服务器模式
