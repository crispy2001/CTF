#!/bin/usr/python3
from pwn import *

context.log_level = "info"

argvs = [" " for i in range(100)]

argvs[0] = "./input"
argvs[65] = "\x00"
argvs[66] = "\x20\x0a\x0d"

stdinfd = open('./stdin', 'wb+') #w+:如果存在此檔案就寫入 不存在就創建此檔並寫入
stdinfd.write(b'\x00\x0a\x00\xff')
stdinfd.seek(0) #移動文件讀取指針到開頭

stderrfd  = open('./stderr', 'wb+')
stderrfd.write(b'\x00\x0a\x02\xff')
stderrfd.seek(0)

r = process(argv = argvs, stdin = stdinfd, stderr = stderrfd)

r.interactive()







