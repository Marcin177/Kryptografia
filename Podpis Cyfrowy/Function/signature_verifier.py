import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import datetime

def verify_signature(sig_file, cert_file, document_file):
    try:
        # Sprawdzenie istnienia plików
        if not all(os.path.exists(file) for file in [sig_file, cert_file, document_file]):
            return "Nie znaleziono jednego z plików"

        # Wczytanie certyfikatu X.509
        with open(cert_file, 'rb') as cert_file_obj:
            cert_data = cert_file_obj.read()
            cert = load_pem_x509_certificate(cert_data, backend=default_backend())

        # Sprawdzenie ważności certyfikatu z użyciem UTC
        current_time = datetime.datetime.now(datetime.timezone.utc)
        if current_time < cert.not_valid_before_utc or current_time > cert.not_valid_after_utc:
            return "Certyfikat utracił ważność"

        # Wydobycie klucza publicznego z certyfikatu
        pub_key = cert.public_key()

        # Wczytanie podpisu z pliku .sig
        with open(sig_file, 'rb') as sig:
            signature = sig.read()

        # Wczytanie danych (oryginalnego dokumentu), które były podpisane
        with open(document_file, 'rb') as doc:
            document_data = doc.read()

        # Sprawdzenie, czy pliki nie są puste
        if len(signature) == 0 or len(document_data) == 0:
            return "Pusty plik podpisu lub dokumentu"

        # Dodatkowa diagnostyka
        print("Diagnostyka:")
        print(f"Długość podpisu: {len(signature)} bajtów")
        print(f"Długość dokumentu: {len(document_data)} bajtów")

        # Obliczenie hasha dokumentu
        document_hash = hashes.Hash(hashes.SHA256())
        document_hash.update(document_data)
        document_hash_value = document_hash.finalize()

        # Próba weryfikacji podpisu - dwie metody
        verification_methods = [
            # Metoda 1: Weryfikacja całego dokumentu
            lambda: pub_key.verify(
                signature,
                document_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            ),
            # Metoda 2: Weryfikacja hasha dokumentu
            lambda: pub_key.verify(
                signature,
                document_hash_value,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        ]

        # Próba weryfikacji kolejnymi metodami
        for method in verification_methods:
            try:
                method()
                return "Podpis jest ważny!"
            except InvalidSignature:
                print("Nieprawidłowy podpis - próba kolejnej metody")
                continue
            except Exception as e:
                print(f"Błąd weryfikacji: {e}")

        # Jeśli żadna metoda nie zadziałała
        return "Podpis jest nieprawidłowy"

    except FileNotFoundError:
        return "Nie znaleziono pliku"
    except PermissionError:
        return "Brak uprawnień do odczytu pliku"
    except ValueError as e:
        return f"Nieprawidłowy format pliku: {e}"
    except Exception as e:
        return f"Błąd podczas weryfikacji podpisu: {str(e)}"