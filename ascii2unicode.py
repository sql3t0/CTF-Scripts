#python2.7

import sys
if len(sys.argv) > 1:
    print(''.join(['\u00'+x.encode('hex') for x in sys.argv[1] ]))
else:
    print(''.join(['\u00'+x.encode('hex') for x in sys.stdin.read()]))
