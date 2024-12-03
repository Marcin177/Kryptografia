from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
import os
from Function.certificates import *  # Przyjmujemy, że masz tam swoje certyfikaty pośrednie i root

class CertificateGenerator:
    def __init__(self, private_key_path, cert_folder, subject_name, pesel_nip, address, representative, valid_days=365):
        self.private_key_path = private_key_path
        self.cert_folder = cert_folder
        self.subject_name = subject_name
        self.pesel_nip = pesel_nip
        self.address = address
        self.representative = representative
        self.valid_days = valid_days

        # Wczytanie certyfikatów z pliku certificates.py
        self.intermediate_key = INTERMEDIATE_CA_PRIVATE_KEY
        self.intermediate_cert = INTERMEDIATE_CA_CERT
        self.root_cert = ROOT_CA_CERT  # Zakładamy, że masz certyfikat root CA w pliku certificates.py

    def generate_certificate(self):
        # Wczytanie klucza prywatnego Intermediate CA
        intermediate_private_key = serialization.load_pem_private_key(
            self.intermediate_key.encode(),
            password=None,
            backend=default_backend()
        )

        # Wczytanie certyfikatu Intermediate CA
        intermediate_cert = x509.load_pem_x509_certificate(
            self.intermediate_cert.encode(),
            default_backend()
        )

        # Wczytanie certyfikatu Root CA
        root_cert = x509.load_pem_x509_certificate(
            self.root_cert.encode(),
            default_backend()
        )

        # Wczytanie już istniejącego klucza prywatnego podmiotu
        with open(self.private_key_path, "rb") as key_file:
            subject_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Tworzenie certyfikatu dla podmiotu
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.subject_name),
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"PL"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, self.address),
            x509.NameAttribute(x509.NameOID.STREET_ADDRESS, self.address),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.representative),
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, self.pesel_nip)  # Dodanie PESEL/NIP jako numer seryjny
        ])

        # Generowanie unikalnego numeru seryjnego
        serial_number = x509.random_serial_number()

        # Tworzenie certyfikatu
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            intermediate_cert.subject  # Emitent to certyfikat Intermediate CA
        ).public_key(
            subject_private_key.public_key()
        ).serial_number(
            serial_number  # Użycie unikalnego numeru seryjnego
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=self.valid_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(intermediate_private_key, hashes.SHA256(), default_backend())

        # Zapisz certyfikat podmiotu
        cert_path = os.path.join(self.cert_folder, "certificate.pem")
        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

        # Tworzenie pliku certyfikatu z certyfikatami pośrednimi i root
        cert_chain_path = os.path.join(self.cert_folder, "certificate_with_chain.pem")
        with open(cert_chain_path, "wb") as chain_file:
            # Zapisz certyfikat podmiotu
            chain_file.write(cert.public_bytes(serialization.Encoding.PEM))
            # Zapisz certyfikat Intermediate CA
            chain_file.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
            # Zapisz certyfikat Root CA
            chain_file.write(root_cert.public_bytes(serialization.Encoding .PEM))

        return cert_path, cert_chain_path