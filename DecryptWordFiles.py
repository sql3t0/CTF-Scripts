#!/usr/bin/python
# pip install msoffcrypto-tool
#
# By Sql3t0
import sys
import msoffcrypto

if len(sys.argv) < 3:
	print "[-] Usage : "
	print "          : python script.py 'encrypted_word_file' 'wordlist_file'"
else:
	file = msoffcrypto.OfficeFile(open(sys.argv[1], "rb"))

	for p in open(sys.argv[2]):
		sys.stdout.write("\r[>] Pass: "+str(p.replace('\n',''))+"	")
		try:
			# Use password
			file.load_key(password=p.replace('\n',''))
			file.decrypt(open("decrypted_"+sys.argv[1], "wb"))
			sys.stdout.write("\r[+] PASSWD FOUND : "+str(p))
			break
		except Exception as e:
			pass

	print '[.] END !'
