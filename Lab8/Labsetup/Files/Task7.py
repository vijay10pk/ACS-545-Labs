#!/usr/bin/python3
 
from Crypto.Cipher import AES
from Crypto.Util import Padding

data = b'This is a top secret.'

expected_ciphertext = '3879c71b232cd0d2fc6f5ffcc1d76f074c0fcbe007d9cc53939fdeebf1d6ffd2'

iv_hex_string  = 'aabbccddeeff00998877665544332211'
iv  = bytes.fromhex(iv_hex_string)
 
f = open('words.txt','r')  
for word in f:
        if(len(word) <= 16):
            k = word.strip()
            key_string = k + ('#' *(16 - len(k)))
            key = bytes.fromhex(key_string.encode('utf-8').hex())
            cipher = AES.new(key, AES.MODE_CBC, iv)                  
            ciphertext = cipher.encrypt(Padding.pad(data, 16))
            if(expected_ciphertext == ciphertext.hex()):
                print ("Key is:",key_string);

