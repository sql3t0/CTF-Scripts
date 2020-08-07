import sys
import hmac
import itertools
import threading
from hashlib import md5


def hmac_md5(key,msg):
	return hmac.HMAC(key, msg, md5).hexdigest()

def bruteHmack(lista):
	key = b"epic"
	target_hash = "aba70621e382c57e0b0173642eb6479c"
	for msg in lista:
		msg = ''.join(msg)
		h = hmac_md5(key,msg.encode('utf-8'))
		sys.stdout.write('\r[>] %s:%s 		'%(msg,h))
		if h == target_hash:
			print("\n[+] Found: %s:%s 		\n" %(msg,h))
			exit()

if __name__ == '__main__':
	for size in range(4,20):
		dic = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-'
		perm = itertools.product(dic, repeat=size)
		threading.Thread(target=bruteHmack,args=(perm,)).start()