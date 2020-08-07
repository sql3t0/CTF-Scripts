#vguvauetkrv
#vguvauetkrv
import sys
import string

def ascii_pp(msg):
	try:
		msg = msg.strip().decode('HEX')
	except Exception as e:
		pass

	#XOR 1byte
	for i in string.ascii_letters:
		r=''
		for x in msg:
			try:
				r += chr(ord(x) ^ ord(i))
			except Exception as e:
				# print '[!] XOR -',e
				pass
				
		print '[XOR]',i,'-',r.strip('\r').replace('\n',''),' [HEX] ',r.encode('HEX')
		#XOR 1byte

	for i in range(100):
		r=''
		for x in msg:
			try:
				r += chr(ord(x) ^ int(i))
			except Exception as e:
				# print '[!] XOR -',e
				pass
				
		print '[XOR]',i,'-',r.strip('\r').replace('\n',''),' [HEX] ',r.encode('HEX')

	r=''
	for i in range(len(msg)):
		try:
			r+= chr(ord(msg[i])+i)
		except Exception as e:
			# print '[!] NEXT_CHR -',e
			pass

	print '[NEXT_CHR-]',i,'-',r.strip('\r').replace('\n',''),' [HEX] ',r.encode('HEX')

	r=''
	for i in range(len(msg)):
		try:
			r+= chr(ord(msg[i])-i)
		except Exception as e:
			# print '[!] PREV_CHR -',e
			pass

	print '[PREV_CHR-]',i,'-',r.strip('\r').replace('\n',''),' [HEX] ',r.encode('HEX')

	for i in range(256):
		r=''
		for x in msg:
			try:
				r += chr(ord(x)+i % 256)
			except Exception as e:
				r += chr(ord(x))
				# print '[!] ASCII+ -',e
				
		print '[ASCII+]',i,'-',r.strip('\r').replace('\n',''),' [HEX] ',r.encode('HEX')

	for i in range(256):
		r=''
		for x in msg:
			try:
				r += chr(ord(x)-i % 256)
			except Exception as e:
				r += chr(ord(x))
				# print '[!] ASCII- -',e

		print '[ASCII-]',i,'-',r.strip('\r').replace('\n',''),' [HEX] ',r.encode('HEX')

if len(sys.argv) <= 1 :
	if not sys.stdin.isatty():
		data = sys.stdin.read()
		print ascii_pp(data.replace('\n',''))
	else:
		print('Usage : scriptname.py "string_sequency"')
		print('      : or ')
		print('      : STDOUT | scriptname.py ')
else:
	if not sys.stdin.isatty():
		data = sys.stdin.read()
	else:
		data = sys.argv[1]
	
	print ascii_pp(data.replace('\n',''))
