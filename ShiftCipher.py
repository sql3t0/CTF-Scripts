#!/usr/bin/env python
#
# By Sql3t0
#
# SHIFT CYPHER

import sys

chars = 26
charsUpper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
charsLower = 'abcdefghijklmnopqrstuvwxyz'

def decrypt(enc):
	for c in range(chars): 
		ret = []
		string = ""
		for e in enc:
			#print c
			if e not in charsUpper and e not in charsLower:
				ret.append(e)
				string += e
			else:
				if e in charsUpper:
					try:
						ret.append((charsUpper.index(e) - c) % 26)
						string += charsUpper[(charsUpper.index(e) - c) % 26]
					except Exception as err:
						pass	
				else:
					try:
						ret.append((charsLower.index(e) - c) % 26)
						string += charsLower[(charsLower.index(e) - c) % 26]
					except Exception as err:
						pass
		#print c,ret
		print c, string

def encrypt(enc):
	for c in range(chars): 
		ret = []
		string = ""
		for e in enc:
			#print c
			if e not in charsUpper and e not in charsLower:
				ret.append(e)
				string += e
			else:
				if e in charsUpper:
					try:
						ret.append((charsUpper.index(e) + c) % 26)
						string += charsUpper[(charsUpper.index(e) + c) % 26]
					except Exception as err:
						pass
				else:
					try:
						ret.append((charsLower.index(e) + c) % 26)
						string += charsLower[(charsLower.index(e) + c) % 26]
					except Exception as err:
						pass
		#print c,ret
		print c, string


if len(sys.argv) >= 2:
	if not sys.stdin.isatty():
		enc = sys.stdin.read().replace('\n','')
	elif len(sys.argv) > 2:
		enc = sys.argv[2]
	else:
		print '[>] Usage: %s ( -e or -d ) "text"'%sys.argv[0]
		exit()	

	if sys.argv[1] == '-d':
		encrypt(enc)
	elif sys.argv[1] == '-e':
		decrypt(enc)
	else:
		print '[!] Invalid Option !\n[>] Usage:  %s ( -d or -e ) "text" ! '%sys.argv[0]
else:
	print '[>] Usage: %s ( -e or -d ) "text"'%sys.argv[0]