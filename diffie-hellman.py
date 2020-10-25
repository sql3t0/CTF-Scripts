#!/usr/bin/python
#secret key(a ?) of A (alice) = 57513
#secret key(b ?) of B (Bob) = 
import sys

enc = 73851709625569149303392944  # encrypted text
p = 131231564657789987221314359   # public prime number  
g = 483905			  # public integer number
# A = (g ** a) % p
A = 38289573795047443088133899    # public key Alice
# B = (g ** b) % p
B = 27036552164913867986554244    # public key Bob
#i=30000 
while i <= 100000:
	secret = ((g**i) % p)
	sys.stdout.write('\r['+str(i)+'] '+str(secret))
	if (secret == A):
		print("\nSecret key[A]: "+str(i));
		a = i
		s = (B ** a) % p
		break
	if (secret == B):
		print("\nSecret key[B]: "+str(i));
		b = i
		s = (A ** b) % p
		break	
	i += 1

print('RSA-key[S]: '+str(s))
flag_hex = format(s ^ enc, 'x')
print("Flag: Hackaflag{" + flag_hex.decode("hex") + "}")
