from pwn import *

xorkey = 2
xored_string = xor(b'flag.txt', xorkey)
print(xored_string)
xor_decode = ""
addr_offset = 0
data_section = 0x601028

for i in xored_string:
	xor_decode += pack(data_section + addr_offset)
	addr_offset += 1
print(xor_decode)