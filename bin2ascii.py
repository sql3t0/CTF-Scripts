#!/usr/bin/env python
#
# By Sql3t0
# chmod +x bin2ascii.py && mov bin2ascii.py bin2ascii && mv bin2ascii /usr/bin
import sys

def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def conv(data):
    text = str(data).replace(' ','')
    str_ = ""
    for code in chunkstring(text,8): 
        code = int(code, 2)
        char = chr(code)
        str_ += char
        
    return str_


if len(sys.argv) <= 1 :
    if not sys.stdin.isatty():
        data = sys.stdin.read()
        print conv(data.replace('\n',''))
    else:
        print('Usage : scriptname.py "string_sequency"')
        print('      : or ')
        print('      : STDOUT | scriptname.py ')
else:
    if not sys.stdin.isatty():
        data = sys.stdin.read()
    else:
        data = sys.argv[1]
    
    print conv(data.replace('\n',''))

    

    
