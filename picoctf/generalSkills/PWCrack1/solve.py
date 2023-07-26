#!/bin/usr/python3
from pwn import *

f = open("./level3.hash.bin", "rb")
#correct = f.decode().read()
correct = f.read()

print(correct)
f.close()

# e1 6d 55 a5 5d 80 dd dd  52 a8 3e ab ea 57 2b 7b
# e16d55a55d80dddd52a83eabea572b7b : 87ab






