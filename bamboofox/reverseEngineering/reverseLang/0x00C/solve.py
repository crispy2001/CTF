#!/bin/usr/python3

arr = [72, 75, 71, 72, 69, 69, 76, 69, 82, 113, 105, 58, 110, 57, 85, 120, 57, 124, 59, 57, 125, 59, 100, 109, 85, 59, 100, 85, 105, 119]
xor_value = 10

for i in range(len(arr)):
	print(chr(arr[i] ^ xor_value), end = "")



