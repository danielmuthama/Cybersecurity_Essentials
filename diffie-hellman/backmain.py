import random                                                       #Nonce Generator
from Crypto.Cipher import AES                                       #Import the cipher libraries
import socket
from Crypto.Random import get_random_bytes                          #Crypto library for random number generation
from time import time                                               #Library to compute the time of execution

host = '127.0.0.1'                                                  #Server Local host IP (Bob)
port =  55639                                                     #UDP server port number
buffersize = 4096
x_bob = 253


ServerSocketB = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #Create a socket object for the server
ServerSocketB.bind((host, port))                                    #Binds the server to the declared IP and port address

while True:                                                          #This while loop continuously listens for connection from the client till a termination is initiated
    data, addr = ServerSocketB.recvfrom(buffersize)                  ###FIRST MESSAGE RECEIVED FROM ALICE
    print ("The message is:", data)
    message = "Hello client i received your message"
    ServerSocketB.sendto(message, addr)                              ##FIRST MESSAGE SENT TO ALICE
    data = ServerSocketB.recvfrom(4096)                              ###SECOND MESSAGE RECEIVED FROM ALICE
    print("The value of alpha, q and Y_a is given as:", data)        #From the sent values, extract the parameters needed to compute y_bob
    print("The first element is:", data[0])
    string = data[0]                                                 #This extracts the string of alpha, q and Y_alice from the tuple
    a = int(string[0])                                               #Convert the first string value to integer for alpha
    q = int(string[2:7])                                             #Concatenate the next 5 string values and convert the values to integer for base q
    y_alice = int(string[8:12])                                      #Concatenate the next 5 string values for Y_alice
    print("Values of a & Y_alice:", a, y_alice)
    print("The extracted value of base q:", int(q))
    def dh_calc(x_bob, q, a):
        y_bob = (a ** x_bob) % q                                     #Calculate value to be shared publicly over the internet

        return y_bob


    y_bob = dh_calc(x_bob, q, a)
    y_bob = str(y_bob)
    print ("Print Y_bob", y_bob)
    ServerSocketB.sendto(y_bob, addr)                               ##SECOND MESSAGE SENT TO ALICE

    def dh_keycompute(y_alice):                                     #Function to compute KEY value in 256 bits value
        dh_calc(x_bob, q, a)
        k = (y_alice ** x_bob) % q
        keyvalue = bin(k)[2:].zfill(32)
        return keyvalue

    bob_key = dh_keycompute(y_alice)

    key = bin(3750)[2:].zfill(32)
    start = time()
    class AESCipher:
        def __init__(self, key):
            self.key = key

        def encrypt(self, message):
            if len(message) % 16 == 0:                              #This performs a modulo operation on the bytes equivalent of a message string
                plaintext = message.encode('utf-8')
                cipher = AES.new(key, AES.MODE_ECB)
                msg = cipher.encrypt(plaintext)
            else:
                length = len(message)
                plaintext = (message + ((16 - length % 16) * str(0)))
                plaintext = plaintext.encode('utf-8')
                cipher = AES.new(key, AES.MODE_ECB)
                msg = cipher.encrypt(plaintext)


            return msg

        def decrypt(self, msg):

            decipher = AES.new(self.key, AES.MODE_ECB)
            plaintext = decipher.decrypt(msg)
            plaintext = plaintext.decode('utf-8')
            plaintext = plaintext.rstrip('0')

            return plaintext

    data = ServerSocketB.recvfrom(4096)                                          ###THIRD MESSAGE RECEIVED FROM ALICE
    #print (data)


    bobclass = AESCipher(key)
    data = data[0]
    bob_decrypt = bobclass.decrypt(data)
    print("Initial challenge received from Alice: ", int(bob_decrypt))

    def randomnumber():
        y = random.getrandbits(32)                                              # Compute a random 32 bits value for Bob's challenge
        binary = "{0:b}".format(y)                                              # Conversion of integer to binary

        return y

    chvalue = randomnumber()                                                    # Obtain a nonce to be sent over the socket
    bob_decrypt = int(bob_decrypt) - 1
    message = str(chvalue)+','+str(bob_decrypt)                             # String representation of the nonce

    bob_encrypt = bobclass.encrypt(message)
    print("The first challenge message sent to Alice: ", chvalue, bob_encrypt)
    ServerSocketB.sendto(bob_encrypt, addr)                                     ##THIRD ENCRYPTED MESSAGE SENT TO ALICE

    #FINAL CHALLENGE HANDSHAKE AUTH
    data = ServerSocketB.recvfrom(4096)                                          ###FOURTH MESSAGE AND FINAL CHALLENGE FROM ALICE
    data = data[0]
    bob_decrypt = bobclass.decrypt(data)

    fin_challenge = int(bob_decrypt)
    print("The final challenge received from Alice: ", fin_challenge)
    if fin_challenge == (chvalue - 1):
        print("The nonce and 1 less are:", chvalue, fin_challenge)

        #with open('Readmee.txt', 'r') as myfile:                               #When reading from large documents of about 4kb
            #message = myfile.read()
        message = "Yippe !! authentication successful, Welcome to our network, it is a pleasure to have you here...................keep going" \
                  "Yippe !! authentication successful, Welcome to our network, it is a pleasure to have you here...................keep going" \
                  "Yippe !! authentication successful, Welcome to our network, it is a pleasure to have you here...................keep going" \
                  "Yippe !! authentication successful, Welcome to our network, it is a pleasure to have you here...................keep going" \
                  "Yippe !! authentication successful, Welcome to our network, it is a pleasure to have you here...................keep going" \
                  "Yippe !! authentication successful, Welcome to our network, it is a pleasure to have you here...................keep going" \

        bob_encrypt = bobclass.encrypt(message)
        end = time()
        print("The duration of execution is: ", end - start)
        ServerSocketB.sendto(bob_encrypt, addr)                                 ##MESSAGE AUTHENTICATION

    else:
        message = "Authentication failure"
        ServerSocketB.sendto(message, addr)                                     ##MESSAGE FAILURE
        break


ServerSocketB.close()