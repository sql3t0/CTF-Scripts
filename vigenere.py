#!/usr/bin/env python
import sys

def cipherText(string, key): 
    cipher_text = [] 
    for i in range(len(string)): 
        x = (ord(string[i]) + 
             ord(key[i])) % 26
        x += ord('A') 
        cipher_text.append(chr(x)) 
    return("" . join(cipher_text)) 

def originalText(cipher_text, key): 
    orig_text = [] 
    for i in range(len(cipher_text)): 
        x = (ord(cipher_text[i]) - 
             ord(key[i]) + 26) % 26
        x += ord('A') 
        orig_text.append(chr(x)) 
    return("" . join(orig_text))


if len(sys.argv) < 4:
    print "Usage: %s [-e][-d] Text key "%sys.argv[0]
    exit()	
else:
    Text = sys.argv[2]
    Key  = sys.argv[3]
    if sys.argv[1] == "-e":
        print cipherText(Text,Key)
    if sys.argv[1] == "-d":
        print originalText(Text,Key)