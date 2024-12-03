from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os

class CertificateAuthorityGenerator:
    def __init__(self, output_folder="certs"):
        self.output_folder = output_folder
        os.makedirs(output_folder, exist_ok=True)

    def generate_root_ca(self, subject_name, valid_days=3650):
        # Generowanie klucza prywatnego Root CA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=8196,
            backend=default_backend()
        )

        # Tworzenie certyfikatu Root CA
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"PL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_name),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{subject_name} Root CA"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=valid_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(private_key, hashes.SHA256(), default_backend())

        # Zapisywanie klucza prywatnego i certyfikatu
        key_path = os.path.join(self.output_folder, "root_ca_key.pem")
        cert_path = os.path.join(self.output_folder, "root_ca_cert.pem")
        with open(key_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

        return key_path, cert_path

    def generate_intermediate_ca(self, root_key_path, root_cert_path, subject_name, valid_days=1825):
        # Wczytanie klucza prywatnego Root CA
        with open(root_key_path, "rb") as key_file:
            root_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Wczytanie certyfikatu Root CA
        with open(root_cert_path, "rb") as cert_file:
            root_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

        # Generowanie klucza prywatnego Intermediate CA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        # Tworzenie certyfikatu Intermediate CA
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"PL"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_name),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{subject_name} Intermediate CA"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            root_cert.subject  # Root CA jako wystawca
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=valid_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        ).sign(root_private_key, hashes.SHA256(), default_backend())

        # Zapisywanie klucza prywatnego i certyfikatu
        key_path = os.path.join(self.output_folder, "intermediate_ca_key.pem")
        cert_path = os.path.join(self.output_folder, "intermediate_ca_cert.pem")
        with open(key_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

        return key_path, cert_path

# Przykład użycia
if __name__ == "__main__":
    generator = CertificateAuthorityGenerator()

    # Tworzenie Root CA
    root_key, root_cert = generator.generate_root_ca(subject_name="Example Root", valid_days=3650)
    print(f"Root CA cert saved: {root_cert}")
    print(f"Root CA key saved: {root_key}")

    # Tworzenie Intermediate CA
    intermediate_key, intermediate_cert = generator.generate_intermediate_ca(
        root_key_path=root_key,
        root_cert_path=root_cert,
        subject_name="Example Intermediate",
        valid_days=1825
    )
    print(f"Intermediate CA cert saved: {intermediate_cert}")
    print(f"Intermediate CA key saved: {intermediate_key}")