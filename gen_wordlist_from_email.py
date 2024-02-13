import re
import sys
import threading

TT_EMAILS = 0
TT_COUNT = 0
TT_PASS = 0

def chunk(xs, n):
    L = len(xs)
    assert 0 < n <= L
    s, r = divmod(L, n)
    t = s + 1
    return ([xs[p:p+t] for p in range(0, r*t, t)] +
            [xs[p:p+s] for p in range(r*t, L, s)])

def genarate_pwd(email, t , i, len_emails):
    sys.stderr.write(f'\r[{TT_COUNT}/{TT_EMAILS}][T{t}:{i}/{len_emails}][{TT_PASS}] {email}\t\t\t\t')
    badstr           = ['com','br','gov','net','sp','gmail','hotmail','outlook','yahoo'] 
    words_from_email = []

    words_from_email = [x for x in re.split(r'\.|\@|_|-', email) if x not in badstr]
    words_from_email = dict.fromkeys(words_from_email)

    commonspecialchrs = ['!','@','#']
    commonssufix      = ['!','#','*','123','1234','321']
    commonpass        = ['123','1234','12345','123456','123456789','654321','321','987654','987654321','adm','admin','administrador','administrator','senha','root','sistema','suporte','rh','teste','janeiro','fevereiro','marco','abril','maio','junho','julho','agosto','setembro','outubro','novembro','dezembro','segunda','terca','quarta','quinta','sexta']
    commonyears       = [str(x) for x in range(1980,2024)]

    def check_len(x):
        global TT_PASS
        if len(x) >= 6:
            print(x)
            TT_PASS +=1
            
    for senha in commonpass:
        for cs in commonssufix+commonyears:
            senhacs = f'{senha}{cs}'
            check_len(senhacs)
            check_len(f'{senhacs.capitalize()}')

            for csc in commonspecialchrs:
                if csc != cs:
                    senhacsccs = f'{senha}{csc}{cs}'
                    check_len(senhacsccs)
                    check_len(f'{senhacsccs.capitalize()}')

    for senha in words_from_email:
        senha = senha.strip()
        
        check_len(senha)
        check_len(senha.capitalize())
        
        for cs in commonssufix+commonyears:
            senhacs = f'{senha}{cs}'
            check_len(senhacs)
            check_len(f'{senhacs.capitalize()}')

            for csc in commonspecialchrs:
                if csc != cs:
                    senhacsccs = f'{senha}{csc}{cs}'
                    check_len(senhacsccs)
                    check_len(f'{senhacsccs.capitalize()}')
            
                for i in range(len(senha)):
                    check_len(f'{senha[0]}{senha[i]}{cs}')
                    check_len(f'{senha[0]}{senha[i]}{csc}{cs}')

def main(emails, t):
    global TT_COUNT
    len_emails = len(emails)
    for i,email in enumerate(emails):
        email = email.lower().strip()
        threading.Thread(target=genarate_pwd,args=(email,t,i,len_emails)).start()
        TT_COUNT +=1

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        emails = (open(sys.argv[1],"r",encoding="iso-8859-15").read()).split('\n')
        TT_EMAILS = len(emails)
        sys.stderr.write(f'[I] Total Emails: {TT_EMAILS}\n')
        if TT_EMAILS >= 30:
            emails = chunk(emails, 30)
        else:
            emails = chunk(emails,len(emails))
        
        for t,email in enumerate(emails):
            threading.Thread(target=main,args=(email,t)).start()
    else:
        sys.stderr.write(f'[?] Usage: {sys.argv[0]} emails.txt\n')
