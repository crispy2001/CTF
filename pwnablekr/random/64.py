#!/bin/usr/python3
from pwn import *

context.log_level = "info"

s = ssh(host = "pwnable.kr", user = "random", port = 2222, password = "guest")
r = s.process("./random")

# since there is no seed in random source code, the random value will be the same everytime.
random_val = 0x000000006b8b4567
ans = 0xdeadbeef ^ random_val

info("ans = %d", ans)
r.sendline(str(ans))
r.interactive()




