import sys

def Fibonacci(n):
	fibs = [0, 1]
	for i in range(2, n+1):
		fibs.append(fibs[-1] + fibs[-2])

	return fibs[n]

def Encrypt(text,s):
	r = ""
	for i in range(len(text)):
		char = text[i] 
		if (char.isupper()):
			r += chr((ord(char) + s-65) % 26 + 65) # Encrypt uppercase characters in plain text
		else:
			r += chr((ord(char) + s - 97) % 26 + 97) # Encrypt lowercase characters in plain text

	return r

if __name__ == '__main__':
	if len(sys.argv) >= 3:
		text = sys.argv[1]
		s = Fibonacci(int(sys.argv[2]))
		print("Shift : %s "%sys.argv[2])
		print("Plain Text : %s "%text)
		print("Shift to Fibonacci : [%s,%s] "%(sys.argv[2],s))
		print("Cipher: %s "%Encrypt(text,s))
	else:
		print("Usage: %s text_to_enc int_value_to_shift")
		print("  E.g: %s TesteDeTexto 6")
	    