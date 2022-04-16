import random                                                   #The use of random library for random numbers
import socket                                                   #The use of socket for client server connection
from time import time                                           #Library to compute the time of execution
from Crypto.Cipher import AES                                   #The use of pycryptodome library for AES encryption
from Crypto.Random import get_random_bytes
start = time()

host = "127.0.0.1"                                              #Local host for socket communication
port = 55639                                                    #UDP server port number

message = "Hello bob, can we start the DH Key Exchange"         #Sample message to be encrypted over the communication link

q = 13063
a = 5                                                           #This is the same has Alpha - Primitive root of q
x_alice = 91

def dh_calc(x_alice, q, a):                                     #Function to Compute Y value for ALice shared to Bob
    y_alice = (a**x_alice) % q                                  #Calculate value to be shared publicly over the internet
    print("Alice sends Y to Bob of value:", y_alice)
    return y_alice

ClientSocketA = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #Create a socket object
ClientSocketA.sendto(message, (host, port))                      ##First MESSAGE SENT TO BOB
y_alice = dh_calc(91,13063,5)
serialmessage = str(a)+','+str(q)+','+str(y_alice)
ClientSocketA.sendto(serialmessage, (host, port))                ##SECOND MESSAGE SENT TO BOB  (the value of q, alpha and Y_a of Alice)

data = ClientSocketA.recvfrom(4096)                              ###FIRST MESSAGE RECEIVED FROM BOB
print (":", data)
data = ClientSocketA.recvfrom(4096)                              ###SECOND MESSAGE RECEIVED FROM BOB
y_bob = data[0]
print ("The computed value of Y Bob is:", y_bob)
y_bob = int(y_bob[0])

def dh_keycompute(y_bob):                                        #Function to compute KEY value in 256 bits value
    k = (y_bob**x_alice)%q
    keyvalue = bin(k)[2:].zfill(32)
    return keyvalue


#print("The key value to be used is: ", dh_keycompute(y_bob))       #Compute the DH key

def randomnumber():
    y = random.getrandbits(32)                                      #Compute a random 32 bits value
    binary = "{0:b}".format(y)                                      #Conversion of integer to binary
                                                                    #Print 32 bits random number
    return y

chvalue = randomnumber()                                            #Obtain a nonce to be sent over the socket
message = str(chvalue)                                              #String representation of the nonce

key = bin(3750)[2:].zfill(32)                                       #Format the key value to 256 bits (AES 256)


class AESCipher:                                                    #AES 128, 192, 256 Cipher Class
    def __init__(self, key):
        self.key = key

    def encrypt(self, message):
        if len(message)%16 == 0:                                    #This performs a modulo operation on the bytes equivalent of a message string
            plaintext = message.encode('utf-8')
            cipher = AES.new(key, AES.MODE_ECB)
            msg = cipher.encrypt(plaintext)
        else:                                                       #This is implemented if message is exactly 128 bits block size
            length = len(message)
            plaintext = (message + ((16 - length % 16) * str(0)))
            plaintext = plaintext.encode('utf-8')
            cipher = AES.new(key, AES.MODE_ECB)
            msg = cipher.encrypt(plaintext)

        #print(msg)
        return msg

    def decrypt(self, msg):

        decipher = AES.new(self.key, AES.MODE_ECB)
        plaintext = decipher.decrypt(msg)
        plaintext = plaintext.decode('utf-8')
        plaintext = plaintext.rstrip('0')
        #print(plaintext)
        return plaintext


aliceclass = AESCipher(key)
alice_encrypt = aliceclass.encrypt(message)
print("The initial nonce sent is: ", message)
print("The encrypted initial nonce sent is: ", alice_encrypt)

ClientSocketA.sendto(alice_encrypt, (host, port))                        ##THIRD ENCRYPTED MESSAGE SENT TO BOB

data = ClientSocketA.recvfrom(4096)                                      ###THIRD ENCRYPTED MESSAGE RECEIVED FROM BOB

print (data)
data = data[0]
alice_decrypt = aliceclass.decrypt(data)
print("Bob's nonce and one less of my previous nonce generated is: ", alice_decrypt)

####### FINAL CHALLENGE HANDSHAKE PROCESS

r = alice_decrypt.index(',')
alice_decrypt = int(alice_decrypt[0:r])
alice_decrypt = alice_decrypt - 1
#print("Bob's nonce minus one is: ", alice_decrypt)
message = str(alice_decrypt)
data = aliceclass.encrypt(message)
print("Final challenge both plain and encr: ", alice_decrypt, data)
ClientSocketA.sendto(data, (host, port))                       ##FOURTH ENCRYPTED MESSAGE SENT TO BOB (FINAL CHALLENGE)

data = ClientSocketA.recvfrom(4096)                            ###FINAL AUTHENTICATION STATUS MESSAGE RECEIVED FROM BOB
data = data[0]
#data = aliceclass.decrypt(data)
print("Final received message is: ", str(data))                      #Encrypted shows successful authentication, unencrypted shows failure




end = time()
print("The duration of execution is: ",end - start)