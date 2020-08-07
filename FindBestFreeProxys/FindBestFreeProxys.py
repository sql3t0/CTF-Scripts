try:
	import re
	import sys
	import time
	import argparse
	import requests
	import threading
	import pandas as pd
	from termcolor import colored
	from tabulate import tabulate
	from requests.packages.urllib3.exceptions import InsecureRequestWarning
	requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception as e:
	module = e[0].replace('No module named ','')
	print('[!] Run : pip install %s'%module)
	print('[!] You must have this module installed to work.')
	exit()

NumberThreads = 0
t0=time.time()

def TimeToResp(df,ip,filename,timeout_=3):
	# print(chr(27) + "[2J")
	global NumberThreads
	protocols = ['http','https']
	ports     = [80,8080,9090,3128]
	rHTTP 	  = []
	rHTTPs 	  = []
	for protocol in protocols:
		for port in ports:
			resp = '*'
			url = '%s://%s:%s/'%(protocol,ip,port)
			sys.stdout.write('\r%s Testing URL             : %s 	  '%(colored('[>]', 'yellow'), colored(url, 'green')))
			try:
				proxy = {protocol: 'http://%s:%s' %(ip, port)}
				url_check = 'http://checkip.dyn.com/'
				validate  = 'Current IP Address:'
				if protocol == 'https':
					url_check = 'https://www.checkip.org/'
					validate  = 'Your IP Address:'

				r = requests.get(url_check, headers = { 'User-Agent': 'Mozilla/5.0' }, timeout=timeout_, verify=False, proxies=proxy)
				if validate in r.content:
					resp = (r.elapsed.total_seconds())
					df.loc[-1] = [protocol,ip,port,resp,url]
					df.index = df.index+1
					df = df.sort_index()
			except Exception as e:
				# print('Error ->\n',e)
				pass

	
	NumberThreads -= 1
	try:
		if NumberThreads <= 0:
			global t0
			d=time.time()-t0; 
			df = df.sort_values(by ='Response' )
			df.set_index('Protocol', inplace=True)
			sys.stdout.write('\r%s Proxys Found in %.2f s.: %s							\n\n%s\n'%(colored('[+]', 'green'), d, colored(len(df.index), 'green'), tabulate(df, headers='keys', tablefmt='psql')))
			if filename != None :
				df.to_csv('%s.csv'%filename, sep=';', decimal=',', index=False)
	except Exception as e:
			print('Error ->',e)
			pass

def DefineContryProxy(country):
	countrys = ['BR','DE','US','IN','ID','UA','RU','TH','CN','FR','PL','ZA','IR','AR','GB','BD','EC','CA','SG','IT']
	country = country.split(',')
	ProxySites = []
	for c in country:
		if c.upper() in countrys:
			ProxySites.append('http://spys.one/proxys/%s/'%c.upper())
		else:
			print('%s Invalid Country !'%colored('[!]','red'))
			exit()

	return ProxySites

def printmore():
	print('\n%s %s :\n'%(colored('[+]','green'),colored('Run the commands below if you want to use a direct proxy on the terminal','yellow')))
	print('#Linux ->')
	print(colored(' #Enable:','green'))
	print('	%s:~# %s'%(colored('root@pcname','red'),colored("export http_proxy='http://proxyServerAddress:proxyPort'",'green')))
	print('	%s:~# %s'%(colored('root@pcname','red'),colored("export https_proxy='https://proxyServerAddress:proxyPort'",'green')))
	print(colored(' #Disable:','yellow'))
	print('	%s:~# %s'%(colored('root@pcname','red'),colored("unset http_proxy='http://proxyServerAddress:proxyPort'",'green')))
	print('	%s:~# %s'%(colored('root@pcname','red'),colored("unset https_proxy='https://proxyServerAddress:proxyPort'",'green')))
	print('\n#Windows ->')
	print(colored(' #Enable','green'))
	print('	%s> %s'%(colored('C:/any/path','red'),colored("set http_proxy='http://proxyServerAddress:proxyPort'",'green')))
	print('	%s> %s'%(colored('C:/any/path','red'),colored("set https_proxy='https://proxyServerAddress:proxyPort'",'green')))
	print(colored(' #Disable','yellow'))
	print('	%s> %s'%(colored('C:/any/path','red'),colored("set http_proxy=''",'green')))
	print('	%s> %s'%(colored('C:/any/path','red'),colored("set https_proxy=''",'green')))
	exit()

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', action='store', dest='timeout', required=False, help='Maximum request time wait. Default value = 3. ( E.g: -t 5 ) ')
	parser.add_argument('-c', action='store', dest='country', required=False, help="Select one or more countries separated by ',' to search for proxies. Suported countrys: [BR,DE,US,IN,ID,UA,RU,TH,CN,FR,PL,ZA,IR,AR,GB,BD,EC,CA,SG,IT] . Default value = BR,EN. ( E.g: -c RU  or -c RU,US ) ")
	parser.add_argument('-o', action='store', dest='filename', required=False, help='Pass the output filename.Standard ext = .csv ( E.g: -o proxys )')
	parser.add_argument('--more', action='store_true', dest='more', help='Shows basic way to set proxy in terminal.')
	arguments = parser.parse_args()
	if arguments.more:
		printmore()

	df = pd.DataFrame(columns=['Protocol','IP','Port','Response','URL'])
	regex = r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'
	ProxySites = ['http://spys.one/free-proxy-list/BR/0','http://spys.one/free-proxy-list/BR/1','http://spys.one/','http://spys.one/en/']
	if arguments.country:
		ProxySites = DefineContryProxy(arguments.country)

	r = ''
	for url in ProxySites:
		r += str(requests.get(url).content)

	ips = re.findall(regex, r)
	ips = list(dict.fromkeys(ips))
	if arguments.timeout:
		timeout_ = int(arguments.timeout)
	else:
		timeout_ = 3

	print('%s Timeout  		    : %s     '%(colored('[>]', 'yellow'), colored(timeout_, 'green')))
	print('%s Countrys                : %s     '%(colored('[>]', 'yellow'), colored(arguments.country, 'green')))
	print('%s Save in file 	    : %s     '%(colored('[>]', 'yellow'), colored(arguments.filename, 'green')))
	print('%s Number of IPs to test   : %s     '%(colored('[>]','yellow'), colored(len(ips), 'green')))
	for ip in ips:
		threading.Thread(target=TimeToResp,args=(df,ip,arguments.filename,timeout_)).start()
		NumberThreads += 1
