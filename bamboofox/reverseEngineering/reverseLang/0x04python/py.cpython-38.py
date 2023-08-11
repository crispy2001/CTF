# uncompyle6 version 3.9.0
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.10 (default, May 26 2023, 14:05:08) 
# [GCC 9.4.0]
# Embedded file name: py.py
# Compiled at: 2020-10-20 11:00:50
# Size of source mod 2**32: 185 bytes
from base64 import b64encode
flag = input('Please input the flag: ')
print(flag)
if b64encode(flag.encode()) == b'QkFNQk9PRk9Ye3VuYzBtcHlsM30=':
    print('OK')
else:
    print('NO')