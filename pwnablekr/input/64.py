#!/bin/usr/python3
from pwn import *
import socket, time

context.delete_corefiles = True

# argvs
argvs = [" " for i in range(100)]
argvs[0] = "./input"
argvs[65] = "\x00"
argvs[66] = "\x20\x0a\x0d"

# stdio
f_stdin = open("./stdin", "wb")
f_stdin.write(b"\x00\x0a\x00\xff")
f_stdin.close()
f_stderr = open("./stderr", "wb")
f_stderr.write(b"\x00\x0a\x02\xff")
f_stderr.close()

# env
env = {"\xde\xad\xbe\xef": "\xca\xfe\xba\xbe"}

# file
f_file = open("./\x0a", "wb")
#f_file = open("/tmp/input/\x0a")
f_file.write(b"\x00\x00\x00\x00")
f_file.close()

# network io
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

conn = ssh(host = "pwnable.kr", user = "input2", port = 2222, password = "guest")
r = conn.process(argv = argvs, stdin = open("./stdin"), stderr=open('./stderr'), env= env)

time.sleep(2)

s.connect(("127.0.0.1", 8888))
s.send("\xde\xad\xbe\xef")
s.close()
r.interactive()







