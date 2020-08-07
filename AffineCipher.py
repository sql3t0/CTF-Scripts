# Implementation of Affine Cipher in Python 

# Extended Euclidean Algorithm for finding modular inverse 
# eg: modinv(7, 26) = 15 
def egcd(a, b): 
	x,y, u,v = 0,1, 1,0
	while a != 0: 
		q, r = b//a, b%a 
		m, n = x-u*q, y-v*q 
		b,a, x,y, u,v = a,r, u,v, m,n 
	gcd = b 
	return gcd, x, y 

def modinv(a, m): 
	gcd, x, y = egcd(a, m) 
	if gcd != 1: 
		return None # modular inverse does not exist 
	else: 
		return x % m 


# affine cipher encrytion function 
# returns the cipher text 
def affine_encrypt(text, key): 
	''' 
	C = (a*P + b) % 26 
	'''
	return ''.join([ chr((( key[0]*(ord(t) - ord('A')) + key[1] ) % 26) 
				+ ord('A')) for t in text.upper().replace(' ', '') ]) 


# affine cipher decryption function 
# returns original text 
def affine_decrypt(cipher, key): 
	''' 
	P = (a^-1 * (C - b)) % 26 
	'''
	return ''.join([ chr((( modinv(key[0], 26)*(ord(c) - ord('A') - key[1])) 
					% 26) + ord('A')) for c in cipher ]) 


# Driver Code to test the above functions 
def main(): 
	# declaring text and key
	import sys 
	text = sys.argv[1]
	key = [17, 20] 

	# calling encryption function 
	affine_encrypted_text = affine_encrypt(text, key) 

	print('Encrypted Text: {}'.format( affine_encrypted_text )) 

	# calling decryption function 
	print('Decrypted Text: {}'.format
	( affine_decrypt(affine_encrypted_text, key) )) 


if __name__ == '__main__': 
	main() 

