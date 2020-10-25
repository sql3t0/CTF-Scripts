# 171b04150f0d191e162d1d0a2e163a06110a050a
try:
	import re
	import time
	import string
	import os,sys
	import argparse
	import threading
	from termcolor import colored
	from itertools import izip, cycle
except Exception as e:
	module = e[0].replace('No module named ','')
	print('[!] Run : pip install %s'%module)
	print('[!] You must have this module installed to work.')
	exit()

NumberThread = 0

def chunk(xs, n):
    L = len(xs)
    assert 0 < n <= L
    s, r = divmod(L, n)
    t = s + 1
    return ([xs[p:p+t] for p in range(0, r*t, t)] +
            [xs[p:p+s] for p in range(r*t, L, s)])

def xor_decrypt(data,keys,regex):
	global NumberThread 
	NumberThread += 1
	try:
		data = data.decode('HEX')
		for key in keys:
			xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
			xored_hex = xored.encode('HEX')
			sys.stdout.write('\r%s %s: %s  | %s: %s   	'%(colored('[%d]'%NumberThread,'yellow'),colored('Passwd','magenta'),colored(key,'yellow'),colored('Hex','magenta'),xored_hex.strip()))
			if re.findall(regex, xored):
				for x in re.findall(regex, xored):
					xored = xored.replace(x,colored(x,'cyan'))
				sys.stdout.write('\r%s %s: %s  |  %s: %s  |  %s: %s  	\n'%(colored('[+]','green'),colored('Passwd','magenta'),colored(key,'green'),colored('Hex','magenta'),xored_hex.strip(),colored('String','magenta'),xored))
	
		NumberThread -= 1
	except Exception as e:
		NumberThread -= 1
		# print e
		pass

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-d', action='store', dest='data', required=True, help='%s ( E.g: -d "hex_to_decode" ) '%(colored('Hex string to XOR decode.','green')))
	parser.add_argument('-t', action='store', dest='threads', required=False, help='Number of Threads.Default value = 50 ( E.g: -t 200 ) ')
	parser.add_argument('-w', action='store', dest='wordlist', required=False, help='Wordlist to bruteforce. Default val = string.printable ( E.g: -w rockyou.txt ) ')
	parser.add_argument('-r', action='store', dest='regex', required=True, help='%s ( E.g: -r "flag|test|secret" ) '%(colored('Regex to search.','green')))
	arguments = parser.parse_args()
	if arguments.threads:
		QtdThreads = int(arguments.threads)
	else:
		QtdThreads = 50

	if arguments.wordlist:
		wordlist   = arguments.wordlist
		passlist   = (open(wordlist,"r").read()).split('\n')
		passlist   = chunk(passlist,int(QtdThreads))
	else:
		passlist   = chunk(string.printable,len(string.printable))

		
	for lista in passlist:
		try:
			threading.Thread(target=xor_decrypt,args=(arguments.data,lista,arguments.regex)).start()
		except Exception as e:
			# print e
			time.sleep(3)
			try:
				threading.Thread(target=xor_decrypt,args=(arguments.data,lista,arguments.regex)).start()
			except Exception as e:
				# print e
				pass
			
