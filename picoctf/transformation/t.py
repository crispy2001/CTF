from pwn import *
#a = "p"
#b = "i"
x = ord(a) << 8
y = ord(b)
#print(x)
#print(y)
w = x + y
#print(w)
x = chr(w)
print(x)
f = open("e", "w")
f.write(x)
f.close()
