import threading
from termcolor import colored
import os, re, sys, platform, subprocess

def info(txt):
    sys.stdout.write(txt)

def ping(host):
    try:
        with open(os.devnull, "wb") as limbo:
            if  platform.system().lower()=="windows":
                r = subprocess.Popen(["ping","-n","1" ,host], stdout=limbo, stderr=limbo).wait()
                cmd = f"ping {host} | egrep -o '\[.*\]'"
                ps = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                IP = ps.communicate()[0].decode('iso-8859-1').strip().replace('[','').replace(']','')
                if r == 0:
                    info(f'\r{colored("[+]", "green")};{host};{IP}\n')
                else:
                    info(f'\r{colored("[-]", "red")};{host};{IP}\n')
            else:
                r = subprocess.Popen(["ping","-c","1" ,host], stdout=limbo, stderr=limbo).wait()
                if r == 0:
                    info(f'\r{colored("[+]", "green")};{host}\n')
                else:
                    info(f'\r{colored("[-]", "red")};{host}\n')
    except Exception as e:
        info(f'\r[>] {host}, ERRO\n')
        print(e)
        pass

if __name__ == '__main__':
    if len(sys.argv) == 2:
        x = '-'
        plist = open(sys.argv[1]).read().split('\n')
        info(f'{colored("[>]", "yellow")} Ping {len(plist)} Hosts \n{x*30}\n')
        for p in plist:
            threading.Thread(target=ping,args=(p,)).start()
    else:
        info(f'[!] Usage: {sys.argv[0]} HostList\n')