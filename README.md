# picoCTF2018 - Magic Padding Oracle
## Text
> Can you help us retreive the flag from this crypto service? Connect with nc 2018shell.picoctf.com 24933. We were able to recover some [Source](https://github.com/PrinceOfBorgo/picoCTF2018-Magic_Padding_Oracle/blob/master/pkcs7.py) Code.

Port may be different.

## Hints
> Paddding Oracle [Attack](https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth)

## Solution
TODO (see script comments)

## Usage
Simply run `padding.py` and insert port to which to connect:
```
$ python padding.py
picoCTF port: 24933

5 blocks of 16 bytes.

Block 5 of ciphertext: 00000000000000000000000000000000

  Retrieving block 4 of ciphertext...
    Byte 16: 0x24
    Byte 15: 0x6c
...
...
    Byte 2: 0xdf
    Byte 1: 0x43

Block 1 of ciphertext: [40, 242, 142, 183, 142, 136, 242, 147, 104, 210, 173, 177, 252, 243, 155, 240]

Ciphertext: 28f28eb78e88f29368d2adb1fcf39bf061ea7ba267c562e51c4a2cc8b910b194f6f9a97bcc224d04c050abd512f721f700aa911a4da9e8ef474f2e48deac6d2600000000000000000000000000000000

Flag: picoCTF{0r4cl3s_c4n_l34k_ae6a1459}
```
