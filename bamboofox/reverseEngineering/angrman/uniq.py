from itertools import permutations
from pwn import *

init_str = "3 EXIT GAME"
died = b"\nYou died\n"
flag = False
for i in range(0, 10):
	if flag == False:
		for j in range(0, 10):
			payload = str(i) + "0" * 4 + str(j)
			p = process("./angrman")
			p.sendlineafter(init_str, b"2")
			p.sendline(payload)
			x = p.recvall()
			if x != died:
				flag = True
				info(x)
				info(payload)
				break
			else:
				info("%d %d", i, j)
				info(x)
