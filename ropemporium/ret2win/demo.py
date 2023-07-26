from pwn import *

context.binary = ELF('./hello')  # 目標二進制文件的路徑

# 指定要使用的終端機
context.terminal = ['xterm', '-e']

p = process(context.binary.path)
gdb.attach(p, gdbscript='''
    break main
    continue
''')

p.recvuntil(b'Breakpoint')

# 在此添加暫停
pause()



p.close()

