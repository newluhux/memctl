# 进程内存操作工具


## 介绍

一个使用C实现的Linux/Android进程内存读写工具

## 依赖

```
libc
```

## 构建

```
cc main.c -o memctl
```

## 使用

```
./memctl
```

## 命令:

```
exit

退出程序
```

```
open pid

打开PID号为pid的进程
```

```
backend backendname

backendname 可选:

procvm	使用 process_vm_xxx 函数
procmem	读写 /proc/pid/mem  文件

设置读写进程内存的方法
```

```
info

格式化输出已经打开的进程信息
```

```
close

关闭进程并清理内存
```

```
dump start len prefix

将start 到 start+len 之间的内存输出到文件:

prefix_pid_start_end.mem
```

```
print address len

把address到address+len 之间的内存使用16进制打印
```

```
write address hex

在address处写入hex，写入长度为strlen(hex)
```

```
search address len hex

在address到address+len区间搜索数据hex
```


## 开发计划:

v 已经实现
x 未实现


v 实现一个类似 dos debug 的界面
x 内置 lisp 解释器用于编写脚本
