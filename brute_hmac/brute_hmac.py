#!/usr/bin/env python3
import hmac
import math
import time
import os,sys
import threading
from hashlib import md5

def saveoutput(filename,text):
	open(filename,"a+").write(text)

def chunk(xs, n):
    L = len(xs)
    assert 0 < n <= L
    s, r = divmod(L, n)
    t = s + 1
    return ([xs[p:p+t] for p in range(0, r*t, t)] +
            [xs[p:p+s] for p in range(r*t, L, s)])

def bruteHmac(lista,t0,NumThreads):
	for passwd in lista:
		passwd = passwd.encode('utf-8')
		tmp = hmac.new(b'epic',passwd,md5).hexdigest()
		sys.stdout.write(f'\r[{NumThreads}] {tmp} 		')
		# if tmp == "aba70621e382c57e0b0173642eb6479c":
		if tmp == "af0daa4fee2a8263840c4849597dba19":
			d=time.time()-t0; 
			print("\n\r[>] Tempo Decorrido: %.2f s.	 \n[+]"%d,tmp,':',passwd,'\n\r[+] FIM 							')
			exit()

if __name__ == '__main__':
	t0=time.time()
	passlist = (open(sys.argv[1],"r",encoding="iso-8859-15").read()).split('\n')
	passlist = chunk(passlist,400)
	NumThreads = 1
	for lista in passlist:
		threading.Thread(target=bruteHmac,args=(lista,t0,NumThreads)).start()
		NumThreads += 1
