#!/usr/bin/env python
#
# By Sql3t0
#

import sys

#Dict Upper
L2I_Up = dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",range(26)))
I2L_Up = dict(zip(range(26),"ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
#Dict Lower
L2I_Lo = dict(zip("abcdefghijklmnopqrstuvwxyz",range(26)))
I2L_Lo = dict(zip(range(26),"abcdefghijklmnopqrstuvwxyz"))

def cipher(ciphertext):
	#print "------------ROTATE ASCII CHARS------------"
	plaintext = ""
	for i in range(26):
		for c in ciphertext:
		    if c.isalpha(): 
		    	if c.isupper():
		    		plaintext += I2L_Up[ (L2I_Up[c] - i)%26 ]
	    		else:
	    			plaintext += I2L_Lo[ (L2I_Lo[c] - i)%26 ]
		    else: 
		    	plaintext += c
		plaintext = plaintext + "\n"     	
	
	return plaintext

def rotateASCIIvalues(ciphertext):
	#print "------------ROTATE ASCII VALUES------------"
	for x in range(26):
		try:
			print ''.join([chr(ord(i)+x) for i in ciphertext])
		except Exception as e:
			pass

if len(sys.argv) <= 1 :
	if not sys.stdin.isatty():
		data = sys.stdin.read()
		print cipher(data.replace('\n',''))
		rotateASCIIvalues(data.replace('\n',''))
	else:
		print('Usage : %s "string_sequency"'%sys.argv[0])
		print('      : or ')
		print('      : STDOUT | %s '%sys.argv[0])
else:
	if not sys.stdin.isatty():
		data = sys.stdin.read()
	else:
		data = sys.argv[1]
	
	print cipher(data.replace('\n',''))
	rotateASCIIvalues(data.replace('\n',''))

