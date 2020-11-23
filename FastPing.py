import ipaddress
import threading
from termcolor import colored
import os, re, sys, platform, subprocess

def info(txt):
    sys.stdout.write(txt)

def chunk(xs, n):
    L = len(xs)
    assert 0 < n <= L
    s, r = divmod(L, n)
    t = s + 1
    return ([xs[p:p+t] for p in range(0, r*t, t)] +
            [xs[p:p+s] for p in range(r*t, L, s)])

def calcsubnet(arg):
    ipi = ipaddress.ip_interface(arg)
    info(f"{colored('[>]', 'yellow')} Address: {ipi.ip}\n")
    info(f"{colored('[>]', 'yellow')} Mask: {ipi.netmask}\n")
    info(f"{colored('[>]', 'yellow')} Cidr: {str(ipi.network).split('/')[1]}\n")
    info(f"{colored('[>]', 'yellow')} Network: {str(ipi.network).split('/')[0]}\n")
    info(f"{colored('[>]', 'yellow')} Broadcast: {ipi.network.broadcast_address}\n")
    return [ str(x) for x in ipaddress.IPv4Network(ipi.network)]

def ping(hosts):
    for host in hosts:
        try:
            IP = ''
            with open(os.devnull, "wb") as limbo:
                if  platform.system().lower()=="windows":
                    r = subprocess.Popen(["ping","-n","1" ,host], stdout=limbo, stderr=limbo).wait()
                    IP = subprocess.Popen("ping -n 1 "+host+" | grep 'Disparando' | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'", shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT).communicate()[0].decode('iso-8859-1').strip()
                    if r == 0:
                        info(f'\r{colored("+", "green")};{host};{IP}\n')
                    else:
                        info(f'\r{colored("-", "red")};{host};{IP}\n')
                else:
                    r = subprocess.Popen(["ping","-c","1" ,host], stdout=limbo, stderr=limbo).wait()
                    if r == 0:
                        info(f'\r{colored("+", "green")};{host}\n')
                    else:
                        info(f'\r{colored("-", "red")};{host}\n')
        except Exception as e:
            info(f'\r[!] {host}, ERRO\n')
            print(e)
            pass

if __name__ == '__main__':
    THREADS = 50
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        if os.path.isfile(arg):
            plist = open(arg).read().split('\n')
        else:
            plist = calcsubnet(arg)
    
        info(f'{colored("[>]", "yellow")} Ping {len(plist)} Hosts \n{chr(0x2d)*30}\n')
        
        if len(plist) >= THREADS:
            plist = chunk(plist, THREADS) # Limit of threads
        else:
            plist = chunk(plist, len(plist))
        
        for p in plist:
            threading.Thread(target=ping,args=(p,)).start()
    else:
        info(f'[!] Usage: {sys.argv[0]} [HostListFromFile or Subnet]\n')
        info(f'[!]   E.g: {sys.argv[0]} myfile.txt\n')
        info(f'[!]   E.g: {sys.argv[0]} 192.168.0.1/24\n')

