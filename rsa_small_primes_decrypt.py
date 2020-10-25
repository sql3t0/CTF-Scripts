#!/usr/bin/python
## RSA - Recover and use private key generated w/ small prime numbers - crypto200-poor_rsa @ alexctf 2017
# @author intrd - http://dann.com.br/ (original script here: http://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e)
# @license Creative Commons Attribution-ShareAlike 4.0 International License - http://creativecommons.org/licenses/by-sa/4.0/
#link de referencia do passo-a-passo para obtencao de P ,Q e N - http://factordb.com/index.php

from Crypto.PublicKey import RSA
import gmpy, base64 , sys

print("\n###########################")
print("#  RSA-Weak_Decrypt-Tool  #")
print("###########################")

if len(sys.argv) <= 4:
	print("Usage : ")
	print("       python scriptName.py 'path_key.pub' val_P val_Q 'cipher_text' ")
	print("       Obs : Calculate P and Q with value of N in http://factordb.com/index.php")
else:
	pub = open(sys.argv[1], "r").read()
	pub = RSA.importKey(pub)

	n = long(pub.n)
	print "\n[n] = "+ str(n)
	e = long(pub.e)
	print "[e] = " + str(e)

	#w/ n, get p and q from factordb.com
	p = int(sys.argv[2]) #62974164538668876966211703057
	print "\n[p] = "+ str(p)
	q = int(sys.argv[3]) #63353793034508312326481912999
	print "[q] = " + str(q)

	d = long(gmpy.invert(e,(p-1)*(q-1)))
	print "[d] = "+ str(d)

	key = RSA.construct((n,e,d))

	## to decrypt
	secret = base64.b64decode(sys.argv[4]) #QJR3Vjp1D/EYZAudVemdvYaFbh3P8+Nl
	#print secret
	print key.decrypt(secret)
	
