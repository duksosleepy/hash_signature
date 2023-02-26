
import sys, json, os
import socket
import gmpy2, os, binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
def simple_rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return gmpy2.powmod(m, numbers.e, numbers.n)

def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return gmpy2.powmod(c, numbers.d, numbers.public_numbers.n)

def int_to_bytes(i):
 # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')
with open('alice_cert', "rb") as cert_file_object:
    global certificate_bytes
    certificate_bytes = cert_file_object.read()

with open('alice_public', "rb") as public_key_file_object:
    global public_key_alice
    public_key_alice = serialization.load_pem_public_key(
                public_key_file_object.read(),
)

with open('alice_private', "rb") as private_key_file_object:
    global private_key_alice
    private_key_alice = serialization.load_pem_private_key(
                    private_key_file_object.read(),
                    password=None)

with open('bob_public', "rb") as public_key_file:
    global public_key_bob
    public_key_bob = serialization.load_pem_public_key(
                public_key_file.read(),
        )
HOST = "127.0.0.1"  
PORT = 65432
if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Sending the certificate...")
        s.sendall(certificate_bytes)
        iden = input("Enter the identity: ").encode('utf-8')
        s.sendall(iden)
        challenge = s.recv(4096)
        challenge = private_key_alice.decrypt(
                                            challenge,
                                            padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                            label=None
            )
        )
        s.sendall(challenge)
        data = s.recv(4096)
        if data == b"Hello":
            while True:
                message = input("Enter the message: ").encode()
                signature_alice = private_key_alice.sign(
                                            message,
                                            padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH
                                    ),
                                    hashes.SHA256()
)
                message = message + signature_alice
                s.sendall(message)
                print("Receiving message...")
                data = s.recv(4096)	
                raw_bytes, signature_bob = data[:-512], data[-512:]
                try:
                    print("Message receive: ",raw_bytes.decode())
                    public_key_bob.verify(signature_bob,
                                            raw_bytes,
                                            padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
        )
                    print("Satify!!")
                except:
                    print("Message had been changed !!")





