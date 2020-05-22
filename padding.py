from pwn import *
from codecs import encode, decode
from binascii import hexlify
from colorama import Fore, Style
import colorama
import json

colorama.init(autoreset = True)

context.log_level = "error"


bs = 16 # block size in bytes
iv = "This is an IV456"
data = {"username":"", "is_admin": "true", "expires":"3000-01-01"}

def pad(s):
	return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

# p[i] = ith block (N bytes) of plaintext to encrypt
# c = ciphertext (hex)
# c1 = (n-1)th block (N bytes) of ciphertext to find
# c2 = nth block (N bytes) of ciphertext
# p2 = p[n] = nth block (N bytes) of plaintext
# i2 = enc(c2) = intermediate state
#
# p2 = c1 ^ i2
# find c'1 with c'1[N-1] such that c'1+c2 has valid padding
# this should give a block of plaintext p'2 such that p'2[N-1] = 1
#
# now set c'1[N-1] such that p'2[N-1] will be 2:
# to do this replace c'1[N-1] with c'1[N-1] ^ 1 ^ 2
# find c'1[N-2] such that c'1+c2 has valid padding
# p'2 will end with two bytes = 2
#
# now set c'1[N-2] and c'1[N-1] so that p'2[N-2] = p'2[N-1] = 3:
# to do this replace c'1[k] with c'1[k] ^ 2 ^ 3, where k = N-2, N-1
# find c'1[N-3] such that c'1+c2 has valid padding
# p'2 will end with three bytes = 3
#
# repeat until all block c'1 has been found
# c'1+c2 will be decrypted to a full block of padding p'2 = [bs..bs]
# 
# find c1 such that c1+c2 decrypts to p2:
# to do this set c1 = c'1 ^ [bs..bs] ^ p2
# p2 = c1 ^ i2 = (c'1 ^ [bs..bs] ^ p2) ^ i2 =
#    = p2 ^ (c'1 ^ i2) ^ [bs..bs] = p2 ^ p'2 ^ [bs..bs] =
#    = p2 ^ [bs..bs] ^ [bs..bs] = p2
#
# do the same for all blocks

port = int(input("picoCTF port: "))

plain = encode(pad(iv + json.dumps(data)), "ascii")
p = [plain[i:i+bs] for i in range(0, len(plain), bs)]
print(f"\n{Fore.CYAN}{Style.BRIGHT}{len(p)}{Style.RESET_ALL} blocks of {Fore.CYAN}{Style.BRIGHT}{bs}{Style.RESET_ALL} bytes.")

c2 = [0]*bs
c = decode(hexlify(bytearray(c2)), "ascii")
print(f"\nBlock {Fore.CYAN}{Style.BRIGHT}{len(p)}{Style.RESET_ALL} of ciphertext: {Fore.GREEN}{Style.BRIGHT}{c}")
for n in range(len(p)-1, 0, -1):
	print(f"\n  Retrieving block {Fore.CYAN}{Style.BRIGHT}{n}{Style.RESET_ALL} of ciphertext...")
	p2 = p[n]
	c1 = [0]*bs
	for pad in range(1,bs+1):
		k = bs-pad
		print(f"    Byte {Fore.CYAN}{Style.BRIGHT}{k+1}{Style.RESET_ALL}: ", end = "")
		for j in range(k+1,bs):
			c1[j] = c1[j] ^ (pad-1) ^ pad

		for i in range(256):
			c1[k] = i

			hex_c = hexlify(bytearray(c1 + c2))
			r = remote("2018shell.picoctf.com", port)
			r.sendlineafter("What is your cookie?\n", hex_c)
			if b"invalid" in r.recvline():
				r.close()
			else:
				r.close()
				print(f"{Fore.GREEN}{Style.BRIGHT}{'0x{:02x}'.format(i)}")
				break
	for j in range(bs):
		c1[j] = c1[j] ^ bs ^ p2[j]

	hex_c1 = decode(hexlify(bytearray(c1)),"ascii")
	print(f"\nBlock {Fore.CYAN}{Style.BRIGHT}{n}{Style.RESET_ALL} of ciphertext: {Fore.GREEN}{Style.BRIGHT}{c1}")
	c = hex_c1 + c
	c2 = c1

print(f"\nCiphertext: {Fore.BLUE}{Style.BRIGHT}{c}")

r = remote("2018shell.picoctf.com", port)
r.sendlineafter("What is your cookie?\n", c)
res = decode(r.recvall(),"ascii")
print(f"\nFlag: {Fore.GREEN}{Style.BRIGHT}{res.split()[-1]}")