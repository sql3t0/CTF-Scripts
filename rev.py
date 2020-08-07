import sys

try:
	print sys.stdin.read()[::-1]
except Exception as e:
	 print '[!] Erro ->',e