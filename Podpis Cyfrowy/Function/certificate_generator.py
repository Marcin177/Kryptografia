from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
import os


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os

class CertificateGenerator:
    def __init__(self, private_key_path, cert_folder, subject_name, pesel_nip, address, representative, valid_days=365):
        self.private_key_path = private_key_path
        self.cert_folder = cert_folder
        self.subject_name = subject_name
        self.pesel_nip = pesel_nip
        self.address = address
        self.representative = representative
        self.valid_days = valid_days

    def generate_certificate(self):
        # Wczytanie klucza prywatnego
        with open(self.private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Tworzenie certyfikatu
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.subject_name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"PL"),  # Dodaj kraj
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.address),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, self.pesel_nip),   # PESEL/NIP
            x509.NameAttribute(NameOID.STREET_ADDRESS, self.address),     # Adres
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.representative),  # Reprezentant
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject  # Self-signed, więc używamy tego samego podmiotu
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=self.valid_days)
        ).sign(private_key, hashes.SHA256(), default_backend())

        # Zapisanie certyfikatu do pliku
        cert_path = os.path.join(self.cert_folder, "certificate.pem")
        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

        return cert_path