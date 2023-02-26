
import sys, json, os
import socket
from ast import literal_eval
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import gmpy2, os, binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
ISSUER_NAME = "fake_cert_authority1"
SUBJECT_KEY = "subject"
ISSUER_KEY = "issuer"
PUBLICKEY_KEY = "public_key"
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
challenge_bytes = os.urandom(32)
with open('bob_public', "rb") as public_key_file_object:
    global public_key_bob
    public_key_bob = serialization.load_pem_public_key(
            public_key_file_object.read(),
)

with open('bob_private', "rb") as private_key_file_object:
    global private_key_bob
    private_key_bob = serialization.load_pem_private_key(
    		private_key_file_object.read(),
    		password=None)

with open('alice_public', "rb") as public_key_file:
    global public_key_alice
    public_key_alice = serialization.load_pem_public_key(
            public_key_file.read(),
)

with open('issuer_public', "rb") as public_key_file_is:
    global issuer_public_key
    issuer_public_key = serialization.load_pem_public_key(
            public_key_file_is.read(),
)
def validate_certificate(certificate_bytes, issuer_public_key):
    raw_cert_bytes, signature = certificate_bytes[:-512], certificate_bytes [-512:]
    issuer_public_key.verify(
            signature,
            raw_cert_bytes,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
    cert_data = json.loads(raw_cert_bytes.decode('utf-8'))
    cert_data[PUBLICKEY_KEY] = cert_data[PUBLICKEY_KEY].encode('utf-8')
    return cert_data
def verify_identity(identity, certificate_data):
    if certificate_data[ISSUER_KEY] != ISSUER_NAME:
        raise Exception("Invalid (untrusted) Issuer!")
    if certificate_data[SUBJECT_KEY] != identity.decode('utf-8'):
        raise Exception("Claimed identity does not match")
def encrypt_bytes(challenge,certificate_data):
    certificate_public_key = serialization.load_pem_public_key(
        certificate_data[PUBLICKEY_KEY],
    )
    ciphertext = certificate_public_key.encrypt(
    				challenge,
    				padding.OAEP(
        			mgf=padding.MGF1(algorithm=hashes.SHA256()),
        			algorithm=hashes.SHA256(),
        label=None
    )
)
    return ciphertext
def decrypt_bytes(response,challenge):
    if response == challenge:
        return True
    else:
        raise Exception("Pulic key dont match")
HOST = "127.0.0.1"
PORT = 65432
if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        print(f"Connected by {addr}")
        data = conn.recv(4096)
        cert_data = validate_certificate(data, issuer_public_key)
        data = conn.recv(4096)
        verify_identity(data,cert_data)
        conn.sendall(encrypt_bytes(challenge_bytes,cert_data))
        data = conn.recv(4096)
        print(data)
        if decrypt_bytes(data,challenge_bytes):
            print("Verify the identity !!!, so you can send the message to Alice.")
            conn.sendall("Hello".encode('utf-8'))
        data = 0
        with conn:
            while True:
                data = conn.recv(4096)
                raw_bytes, signature_alice = data[:-512], data[-512:]
                try:
                    print("Message receive: ",raw_bytes.decode())
                    public_key_alice.verify(signature_alice,
                                            raw_bytes,
                                            padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH
                    ),
                            hashes.SHA256()
    )
                    print("Satify!!")
                except:
                    raise Exception("Message had been changed !!")
                reply = input("Enter the reply message: ").encode('utf-8')
                signature_bob = private_key_bob.sign(reply,
                                    padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
    )
                    
                reply = reply + signature_bob
                conn.sendall(reply)
                print("Receiving message...")
