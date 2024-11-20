from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os


class KeyGenerator:
    def __init__(self, folder, key_size=4096):
        self.folder = folder
        self.key_size = key_size

    def generate_key_pair(self):
        # Generowanie pary kluczy RSA z eksponentem 65537 (często używanym dla podpisu cyfrowego)
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Eksponent publiczny dla podpisu
            key_size=self.key_size,
            backend=default_backend()
        )

        # Uzyskanie klucza publicznego
        public_key = private_key.public_key()

        # Zapisanie kluczy do plików
        private_key_path = os.path.join(self.folder, "private_key.pem")
        public_key_path = os.path.join(self.folder, "public_key.pem")

        # Zapisanie klucza prywatnego
        with open(private_key_path, "wb") as private_pem:
            private_pem.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Zapisanie klucza publicznego
        with open(public_key_path, "wb") as public_pem:
            public_pem.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        return private_key_path, public_key_path