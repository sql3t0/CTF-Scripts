import urllib2,sys

def urlencode(s):
    return urllib2.quote(s)

def urldecode(s):
    return urllib2.unquote(s).decode('utf8')

if len(sys.argv) >= 3 :
	if sys.argv[1] == "-d":
		print urldecode(sys.argv[2])
	if sys.argv[1] == "-e":
		print urlencode(sys.argv[2])
else :
	print('Usage: python script.py [-d]or[-e] "text"')
    