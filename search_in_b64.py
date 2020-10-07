import re
from base64 import b64decode as d64


token = b'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJOQ2FmUXZVcFROb0drRnZLbzNuR2o2eVBLcThSQTkzeWNVaTJZZHlkb1BzIn0'
# print(d64(token + b'='  * (-len(token) % 4) ))
for x in range(len(token)):
    try:
        for y in range(len(token)):
            try:
                tmp = d64(token[x:y+1] + b'=' * (-len(token) % 4) )
                print(tmp.decode('ISO-8859-1'))
            except Exception as e:
                pass
    except Exception as e:
        # print(e)
        pass
