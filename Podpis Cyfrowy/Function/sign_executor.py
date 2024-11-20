from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import os

def load_certificate_and_private_key(pem_file_path, password=None):
    with open(pem_file_path, "rb") as pem_file:
        pem_data = pem_file.read()

    private_key = load_pem_private_key(pem_data, password=password, backend=default_backend())
    return private_key, None
