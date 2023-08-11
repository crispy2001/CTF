#!/bin/usr/python3
from pwn import *

key = list(range(0, 15))

# _end = last 5
# secret + 5 = last 10 

p = process("./angrman")
payload = chr(27) * 4 + chr(93) * 11
p.sendlineafter("3 EXIT GAME", b"2")
p.sendline(payload)
tmp = p.recvall()
info("tmp = %s", tmp)
p.interactive()
print("secret5 =", secret5)



