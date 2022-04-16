import string


p=int(input('Enter prime p: '))
q=int(input('Enter prime q: '))
print("Choosen primes:\np=" + str(p) + ", q=" + str(q) + "\n")
n=p*q
print("n = p * q = " + str(n) + "\n")
phi=(p-1)*(q-1)
print("Euler's function (totient) [phi(n)]: " + str(phi) + "\n")

def gcd(a, b):
    while b != 0:
        c = a % b
        a = b
        b = c
    return a

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def coprimes(a):
    l = []
    for x in range(2, a):
        if gcd(a, x) == 1 and modinv(x,phi) != None:
            l.append(x)
    for x in l:
        if x == modinv(x,phi):
            l.remove(x)
    return l

print("Choose an e from a below coprimes array:\n")
print(str(coprimes(phi)) + "\n")
e=int(input())
d=modinv(e,phi)
print("\nYour public key is a pair of numbers (e=" + str(e) + ", n=" + str(n) + ").\n")
print("Your private key is a pair of numbers (d=" + str(d) + ", n=" + str(n) + ").\n")
def encrypt_block(m):
    c =(m**e)%n
    print(c)
    if c == None: print('No modular multiplicative inverse for block ' + str(m) + '.')
    return c
def decrypt_block(c):
    print(c)
    m=(c**d)%n
    if m == None: print('No modular multiplicative inverse for block ' + str(c) + '.')
    return m
def encrypt_string(s):
    return ''.join([chr(encrypt_block(ord(x))) for x in list(s)])
def decrypt_string(s):
    return ''.join([chr(decrypt_block(ord(x))) for x in list(s)])

s = input("Enter a message to encrypt: ")
print("\nPlain message: " + s + "\n")
enc = encrypt_string(s)
print("Encrypted message: " + enc + "\n")
dec = decrypt_string(enc)
print("Decrypted message: " + dec + "\n")