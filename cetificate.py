from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import sys, json, os
ISSUER_NAME = "fake_cert_authority1"
SUBJECT_KEY = "subject"
ISSUER_KEY = "issuer"
PUBLICKEY_KEY = "public_key"
def create_fake_certificate(pem_public_key, subject, issuer_private_key):
    certificate_data = {}
    certificate_data[SUBJECT_KEY] = subject
    certificate_data[ISSUER_KEY] = ISSUER_NAME
    certificate_data[PUBLICKEY_KEY] = pem_public_key.decode('utf-8')
    raw_bytes = json.dumps(certificate_data).encode('utf-8')
    signature = issuer_private_key.sign(
            raw_bytes,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
    ),
        hashes.SHA256()
    )
    return raw_bytes + signature
if __name__=="__main__":
    while True:
        certificate_output_file = input("\nEnter a file name for new certificate: ")
        issuer_private_key_file = input("\nEnter a file name private issuer certificate: ")
        certificate_subject_public_key_file = input("\nEnter a file name public key: ")
        certificate_subject = input("\nEnter your name: ")
        if os.path.exists(certificate_output_file):
            print("File already exists.")
        else:
            with open(certificate_output_file, "wb+") as certificate_file_object:
                with open(issuer_private_key_file, "rb") as private_key_file_object:
                    issuer_private_key = serialization.load_pem_private_key(
                                private_key_file_object.read(),
                                backend=default_backend(),
                                password=None)
                    with open(certificate_subject_public_key_file, "rb") as public_key_file_object:
                        certificate_subject_public_key_bytes = public_key_file_object.read()
                        certificate_bytes = create_fake_certificate(certificate_subject_public_key_bytes,
                                    certificate_subject,
                                    issuer_private_key)
                        certificate_file_object.write(certificate_bytes)
