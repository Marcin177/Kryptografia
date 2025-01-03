import random
import math
import os
from datetime import datetime
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
from tkinter import filedialog, messagebox
import mimetypes
import socket
import threading
import time
import psutil
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

server_thread = None

def encode_aes(key):
    key = hashlib.sha256(key.encode()).digest()
    return key
def encode_des(key):
    if isinstance(key, str):
        key = key.encode()
    if len(key) < 8:
        key = key.ljust(8, b'\0')
    elif len(key) > 8:
        key = key[:8]
    return key
def podstawieniowe_szyfrowanie(tekst):
    kod_ascii = random.randint(65, 97)
    przesuniecie = kod_ascii - 64
    zaszyfrowany = ""
    for char in tekst:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            zaszyfrowany += chr((ord(char) - ascii_offset + przesuniecie) % 26 + ascii_offset)
        else:
            zaszyfrowany += char
    return zaszyfrowany + chr(kod_ascii)

def podstawieniowe_deszyfrowanie(zaszyfrowany_tekst):
    kod_ascii = ord(zaszyfrowany_tekst[-1])
    przesuniecie = kod_ascii - 64
    tekst = zaszyfrowany_tekst[:-1]
    odszyfrowany = ""
    for char in tekst:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            odszyfrowany += chr((ord(char) - ascii_offset - przesuniecie) % 26 + ascii_offset)
        else:
            odszyfrowany += char
    return odszyfrowany

def transpozycyjne_szyfrowanie(tekst):
    tekst = tekst.replace(' ', '#')
    dlugosc_tekstu = len(tekst)
    kolumny = random.randint(2, math.ceil(dlugosc_tekstu / 2))
    wiersze = math.ceil(dlugosc_tekstu / kolumny)
    tabela = [[' ' for _ in range(kolumny)] for _ in range(wiersze)]
    index = 0
    for i in range(wiersze):
        for j in range(kolumny):
            if index < len(tekst):
                tabela[i][j] = tekst[index]
                index += 1
            else:
                tabela[i][j] = '#'
    obrot = random.randint(1, 2)
    if obrot == 1:
        tabela = list(zip(*tabela[::-1]))
        tabela = [list(row) for row in tabela]
        kolumny, wiersze = wiersze, kolumny
    elif obrot == 2:
        tabela = list(zip(*tabela))[::-1]
        tabela = [list(row) for row in tabela]
        kolumny, wiersze = wiersze, kolumny
    wynik = []
    for i in range(wiersze):
        for j in range(kolumny - 1, -1, -1):
            wynik.append(tabela[i][j])
    zaszyfrowany_tekst = f"{kolumny}${wiersze}${obrot} " + ''.join(wynik)
    return zaszyfrowany_tekst

def transpozycyjne_deszyfrowanie(zaszyfrowany_tekst):
    naglowek = zaszyfrowany_tekst.split(' ')[0]
    kolumny, wiersze, obrot = map(int, naglowek.split('$'))
    zaszyfrowany_tekst = zaszyfrowany_tekst.split(' ', 1)[1]
    tabela = [[' ' for _ in range(kolumny)] for _ in range(wiersze)]
    index = 0
    wynik = []
    for i in range(wiersze):
        for j in range(kolumny):
            if index < len(zaszyfrowany_tekst):
                tabela[i][kolumny-j-1] = zaszyfrowany_tekst[index]
                index += 1
    if obrot == 1:
        for j in range(kolumny - 1, -1, -1):
            for i in range(wiersze):
                wynik.append(tabela[i][j])
    elif obrot == 2:
        for j in range(kolumny):
            for i in range(wiersze - 1, -1, -1):
                wynik.append(tabela[i][j])
    tekst = ''.join(wynik).replace('#', ' ')
    return tekst

def des_szyfrowanie(plain_text, global_key):
    key = encode_des(global_key)
    cipher = DES.new(key, DES.MODE_CBC)
    padded_text = pad(plain_text.encode(), DES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(cipher.iv + encrypted_text).decode('utf-8')

def des_deszyfrowanie(encrypted_text, global_key):
    key = encode_des(global_key)
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_data[DES.block_size:]), DES.block_size)
    return decrypted_text.decode()

def aes_szyfrowanie(tekst, global_key):
    key = encode_aes(global_key)
    cipher = AES.new(key, AES.MODE_CBC)
    padded_text = pad(tekst.encode(), AES.block_size)
    zaszyfrowany_tekst = cipher.encrypt(padded_text)
    return base64.b64encode(cipher.iv + zaszyfrowany_tekst).decode('utf-8')

def aes_deszyfrowanie(zaszyfrowany_tekst_base64, global_key):
    zaszyfrowany_tekst = base64.b64decode(zaszyfrowany_tekst_base64)
    key = encode_aes(global_key)
    iv = zaszyfrowany_tekst[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(zaszyfrowany_tekst[AES.block_size:]), AES.block_size)
    return decrypted_text.decode()

def des_deszyfrowanie_plik(plik_sciezka, global_key):
    key = encode_des(global_key)
    with open(plik_sciezka, 'rb') as f:
        zaszyfrowany_data = f.read()
    iv = zaszyfrowany_data[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    typ_pliku_length = 50
    typ_pliku = zaszyfrowany_data[DES.block_size:DES.block_size + typ_pliku_length].decode('utf-8').strip()
    odszyfrowany_data = unpad(cipher.decrypt(zaszyfrowany_data[DES.block_size + typ_pliku_length:]),
                              DES.block_size)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    odszyfrowany_nazwa = os.path.join(filedialog.askdirectory(title="Wybierz folder do zapisu odszyfrowanego pliku"),
                                      f'odszyfrowany_plik_des_{timestamp}.{typ_pliku}')
    with open(odszyfrowany_nazwa, 'wb') as f:
        f.write(odszyfrowany_data)

def des_szyfrowanie_plik(plik_sciezka, global_key):
    key = encode_des(global_key)
    cipher = DES.new(key, DES.MODE_CBC)
    with open(plik_sciezka, 'rb') as f:
        data = f.read()
    typ_pliku, _ = mimetypes.guess_type(plik_sciezka)
    typ_pliku = typ_pliku.split('/')[-1] if typ_pliku else 'bin'
    typ_pliku_padded = typ_pliku.ljust(50)
    padded_data = pad(data, DES.block_size)
    zaszyfrowany_data = cipher.encrypt(padded_data)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    zaszyfrowany_nazwa = os.path.join(filedialog.askdirectory(title="Wybierz folder do zapisu zaszyfrowanego pliku"),
                                      f'zaszyfrowany_plik_des_{timestamp}.bin')
    with open(zaszyfrowany_nazwa, 'wb') as f:
        f.write(cipher.iv + typ_pliku_padded.encode('utf-8') + zaszyfrowany_data)

def aes_szyfrowanie_plik(plik_sciezka, global_key):
    key = encode_aes(global_key)
    cipher = AES.new(key, AES.MODE_CBC)
    with open(plik_sciezka, 'rb') as f:
        data = f.read()
    typ_pliku, _ = mimetypes.guess_type(plik_sciezka)
    typ_pliku = typ_pliku.split('/')[-1] if typ_pliku else 'bin'
    typ_pliku_padded = typ_pliku.ljust(50)
    padded_data = pad(data, AES.block_size)
    zaszyfrowany_data = cipher.encrypt(padded_data)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    zaszyfrowany_nazwa = os.path.join(filedialog.askdirectory(title="Wybierz folder do zapisu zaszyfrowanego pliku"),
                                      f'zaszyfrowany_plik_aes_{timestamp}.bin')
    with open(zaszyfrowany_nazwa, 'wb') as f:
        f.write(cipher.iv + typ_pliku_padded.encode('utf-8') + zaszyfrowany_data)

def aes_deszyfrowanie_plik(plik_sciezka, global_key):
    key = encode_aes(global_key)
    with open(plik_sciezka, 'rb') as f:
        zaszyfrowany_data = f.read()
    iv = zaszyfrowany_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    typ_pliku_length = 50
    typ_pliku = zaszyfrowany_data[AES.block_size:AES.block_size + typ_pliku_length].decode('utf-8').strip()
    odszyfrowany_data = unpad(cipher.decrypt(zaszyfrowany_data[AES.block_size + typ_pliku_length:]), AES.block_size)  # Deszyfrowanie
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    odszyfrowany_nazwa = os.path.join(filedialog.askdirectory(title="Wybierz folder do zapisu odszyfrowanego pliku"),
                                      f'odszyfrowany_plik_aes_{timestamp}.{typ_pliku}')
    with open(odszyfrowany_nazwa, 'wb') as f:
        f.write(odszyfrowany_data)


def send_text(address, port, plain_text, current_cipher_type, global_key):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            try:
                s.connect((address, port))
                if current_cipher_type == "DES":
                    text = des_szyfrowanie_strumieniowe(plain_text, global_key)
                elif current_cipher_type == "AES":
                    text = aes_szyfrowanie_strumieniowe(plain_text, global_key)
                else:
                    text = "Bład danych"
                s.sendall(text.encode('utf-8'))
                return True
            except ConnectionRefusedError:
                messagebox.showerror("Błąd",
                                     f"Połączenie odrzucone \n upewnij się, że serwer nasłuchuje")
                print("Połączenie odrzucone - upewnij się, że serwer nasłuchuje")
                return False
            except TimeoutError:
                messagebox.showerror("Błąd", f"TimeoutError: KLient nie odpowiada\n Sprawdź poprawność adresu ip portu, klucza lub typu szyfrowania!")
                print("TimeoutError: Serwer nie odpowiada")
                return False
            except Exception as e:
                messagebox.showerror("Błąd", f"Błąd podczas próby połączenia: {e}")

                print(f"Błąd podczas próby połączenia: {e}")
                return False
    except OSError as e:
        print(f"Błąd gniazda: {e}")
        return False

def receive_text(expected_address, port, stop_event, display_func, current_cipher_type, global_key):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(1)
        print(f"Nasłuchiwanie na porcie {port}...")

        server_socket.settimeout(1)  # Ustaw timeout na 1 sekundę

        while not stop_event.is_set():  # Sprawdź, czy flaga zatrzymania jest ustawiona
            try:
                conn, addr = server_socket.accept()
                print(f"Połączenie od {addr}")
                client_ip = addr[0]
                client_port = addr[1]

                if client_ip == expected_address:
                    print(f"Zaakceptowano połączenie od {addr}")
                    with conn:
                        data = conn.recv(1024)
                        if data:
                            received_text = data.decode('utf-8')
                            print(f"Odebrano: {received_text}")
                            if current_cipher_type == "DES":
                                text = des_deszyfrowanie_strumieniowe(received_text, global_key)
                            elif current_cipher_type == "AES":
                                text = aes_deszyfrowanie_strumieniowe(received_text, global_key)
                            else:
                                text = "Bład danych"
                            display_func(text)  # Wywołanie funkcji do wyświetlenia wiadomości
                else:
                    print(f"Odrzucono połączenie od nieautoryzowanego adresu: {addr}")
                    conn.close()
            except socket.timeout:
                continue  # Po prostu kontynuuj, jeśli wystąpił timeout

    except Exception as e:
        print(f"Błąd serwera: {e}")
    finally:
        print("Zamykam gniazdo serwera...")
        server_socket.close()

# Funkcja do uruchamiania serwera w osobnym wątku
def start_server(address, port):
    global server_thread
    server_thread = threading.Thread(target=receive_text, args=(address, port))
    server_thread.daemon = True
    server_thread.start()
    return server_thread

def send_text_DH(address, port, plain_text, current_cipher_type, key):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            try:
                s.connect((address, port))
                text = DH_szyfrowanie(plain_text, key)
                s.sendall(text.encode('utf-8'))
                return True
            except ConnectionRefusedError:
                messagebox.showerror("Błąd",
                                     f"Połączenie odrzucone \n upewnij się, że serwer nasłuchuje")
                print("Połączenie odrzucone - upewnij się, że serwer nasłuchuje")
                return False
            except TimeoutError:
                messagebox.showerror("Błąd", f"TimeoutError: KLient nie odpowiada\n Sprawdź poprawność adresu ip portu, klucza lub typu szyfrowania!")
                print("TimeoutError: Serwer nie odpowiada")
                return False
            except Exception as e:
                messagebox.showerror("Błąd", f"Błąd podczas próby połączenia: {e}")

                print(f"Błąd podczas próby połączenia: {e}")
                return False
    except OSError as e:
        print(f"Błąd gniazda: {e}")
        return False

def receive_text_DH(expected_address, port, stop_event, display_func, current_cipher_type, key):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(1)
        print(f"Nasłuchiwanie na porcie {port}...")

        server_socket.settimeout(1)  # Ustaw timeout na 1 sekundę

        while not stop_event.is_set():  # Sprawdź, czy flaga zatrzymania jest ustawiona
            try:
                conn, addr = server_socket.accept()
                print(f"Połączenie od {addr}")
                client_ip = addr[0]
                client_port = addr[1]

                if client_ip == expected_address:
                    print(f"Zaakceptowano połączenie od {addr}")
                    with conn:
                        data = conn.recv(1024)
                        if data:
                            received_text = data.decode('utf-8')
                            print(f"Odebrano: {received_text}")
                            text = DH_deszyfrowanie(received_text, key)
                            display_func(text)  # Wywołanie funkcji do wyświetlenia wiadomości
                else:
                    print(f"Odrzucono połączenie od nieautoryzowanego adresu: {addr}")
                    conn.close()
            except socket.timeout:
                continue  # Po prostu kontynuuj, jeśli wystąpił timeout

    except Exception as e:
        print(f"Błąd serwera: {e}")
    finally:
        print("Zamykam gniazdo serwera...")
        server_socket.close()



def des_szyfrowanie_strumieniowe(plain_text, global_key):
    key = encode_des(global_key)
    cipher = DES.new(key, DES.MODE_CFB)
    iv = cipher.iv
    encrypted_text = cipher.encrypt(plain_text.encode())
    return base64.b64encode(iv + encrypted_text).decode('utf-8')

def des_deszyfrowanie_strumieniowe(encrypted_text, global_key):
    key = encode_des(global_key)
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CFB, iv)
    decrypted_text = cipher.decrypt(encrypted_data[DES.block_size:])
    return decrypted_text.decode()

def aes_szyfrowanie_strumieniowe(tekst, global_key):
    key = encode_aes(global_key)
    cipher = AES.new(key, AES.MODE_CFB)
    iv = cipher.iv
    encrypted_text = cipher.encrypt(tekst.encode())
    return base64.b64encode(iv + encrypted_text).decode('utf-8')

def aes_deszyfrowanie_strumieniowe(zaszyfrowany_tekst_base64, global_key):
    zaszyfrowany_tekst = base64.b64decode(zaszyfrowany_tekst_base64)
    key = encode_aes(global_key)
    iv = zaszyfrowany_tekst[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_text = cipher.decrypt(zaszyfrowany_tekst[AES.block_size:])
    return decrypted_text.decode()

# Funkcja do szyfrowania tekstu
def rsa_szyfrowanie(text, global_public_key):
    # Załadowanie klucza publicznego RSA
    public_key = RSA.import_key(global_public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # Podział tekstu na mniejsze kawałki
    chunk_size = public_key.size_in_bytes() - 42  # Zostawiamy miejsce na padding
    chunks = [text[i:i+chunk_size].encode() for i in range(0, len(text), chunk_size)]

    encrypted_data = b''
    for chunk in chunks:
        encrypted_data += cipher_rsa.encrypt(chunk)

    # Kodowanie w base64, aby łatwiej było przechowywać wynik
    return base64.b64encode(encrypted_data).decode()

def rsa_deszyfrowanie(encrypted_text, global_private_key):
    # Załadowanie klucza prywatnego RSA
    private_key = RSA.import_key(global_private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Dekodowanie z base64
    encrypted_data = base64.b64decode(encrypted_text.encode())

    # Odszyfrowanie danych w porcjach
    decrypted_data = b''
    for i in range(0, len(encrypted_data), private_key.size_in_bytes()):
        chunk = encrypted_data[i:i+private_key.size_in_bytes()]
        decrypted_data += cipher_rsa.decrypt(chunk)

    return decrypted_data.decode()
def rsa_szyfrowanie_plik(plik_sciezka, global_public_key):
    # Załadowanie klucza publicznego RSA
    public_key = RSA.import_key(global_public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key)

    # Odczytanie pliku
    with open(plik_sciezka, 'rb') as f:
        data = f.read()

    # Odczytanie rozszerzenia pliku
    file_extension = os.path.splitext(plik_sciezka)[1].lstrip('.')

    # Podział pliku na mniejsze kawałki
    chunk_size = public_key.size_in_bytes() - 42  # Zostawiamy miejsce na padding
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

    encrypted_data = b''
    for chunk in chunks:
        encrypted_data += cipher_rsa.encrypt(chunk)

    # Wybór folderu do zapisu zaszyfrowanego pliku
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    folder = filedialog.askdirectory(title="Wybierz folder do zapisu zaszyfrowanego pliku")
    encrypted_file_name = os.path.join(folder, f'zaszyfrowany_plik_rsa_{timestamp}.{file_extension}')

    # Zapisanie zaszyfrowanych danych
    with open(encrypted_file_name, 'wb') as f:
        f.write(encrypted_data)

    messagebox.showinfo("Sukces", "Plik został zaszyfrowany i zapisany.")

def rsa_deszyfrowanie_plik(plik_sciezka, global_private_key):
    # Załadowanie klucza prywatnego RSA
    private_key = RSA.import_key(global_private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Odczytanie zaszyfrowanego pliku
    with open(plik_sciezka, 'rb') as f:
        encrypted_data = f.read()

    # Podział zaszyfrowanych danych na kawałki
    chunk_size = private_key.size_in_bytes()
    decrypted_data = b''
    for i in range(0, len(encrypted_data), chunk_size):
        chunk = encrypted_data[i:i+chunk_size]
        decrypted_data += cipher_rsa.decrypt(chunk)

    # Odczytanie rozszerzenia pliku z nazwy (jeśli zostało zapisane)
    file_extension = os.path.splitext(plik_sciezka)[1].lstrip('.')

    # Wybór folderu do zapisania odszyfrowanego pliku
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    folder = filedialog.askdirectory(title="Wybierz folder do zapisu odszyfrowanego pliku")
    decrypted_file_name = os.path.join(folder, f'odszyfrowany_plik_rsa_{timestamp}.{file_extension}')

    # Zapisanie odszyfrowanych danych
    with open(decrypted_file_name, 'wb') as f:
        f.write(decrypted_data)

    messagebox.showinfo("Sukces", "Plik został odszyfrowany i zapisany.")

def is_process_running(exe_name):
    for process in psutil.process_iter(['name']):
        if process.info['name'] == exe_name:
            return True
    return False




# Funkcja do obliczania wspólnego sekretu
def compute_shared_secret(public_key, private_key):
    pub_key = int(public_key)
    print(pub_key)
    priv_key = int(private_key)
    print(priv_key)
    number = pub_key ** priv_key % 15485863
    print(number)
    return number


def prepare_key(key):
    """Przygotowuje klucz - konwertuje string na 16 bajtów używając hash"""
    if not key or str(key).strip() == '':  # Konwersja key na string przed sprawdzeniem
        raise ValueError("Klucz nie może być pusty")

    # Konwertuj klucz na string jeśli nie jest stringiem
    key_str = str(key)

    # Użyj SHA-256 do wygenerowania klucza
    hash_object = hashlib.sha256(key_str.encode())
    return hash_object.digest()[:16]

def DH_szyfrowanie(tekst, key):
    try:
        if not tekst:
            return "Błąd: Pusty tekst do zaszyfrowania"

        # Przygotuj klucz
        key_bytes = prepare_key(key)

        # Generuj IV
        iv = os.urandom(16)

        # Przygotuj tekst
        text_bytes = tekst.encode('utf-8')
        padding_length = 16 - (len(text_bytes) % 16)
        text_bytes += bytes([padding_length]) * padding_length

        # Szyfrowanie
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(text_bytes)

        # Zwróć IV + zaszyfrowane dane
        return base64.b64encode(iv + encrypted).decode('utf-8')

    except Exception as e:
        return f"Błąd szyfrowania: {str(e)}"


def DH_deszyfrowanie(zaszyfrowany_tekst, key):
    try:
        if not zaszyfrowany_tekst:
            return "Błąd: Pusty tekst do odszyfrowania"

        # Przygotuj klucz
        key_bytes = prepare_key(key)

        try:
            # Dekoduj base64
            encrypted_data = base64.b64decode(zaszyfrowany_tekst)
        except:
            return "Błąd: Nieprawidłowy format zaszyfrowanych danych"

        if len(encrypted_data) < 16:
            return "Błąd: Za krótkie zaszyfrowane dane"

        # Rozdziel IV i zaszyfrowane dane
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Deszyfrowanie
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        try:
            # Usuń padding
            padding_length = decrypted[-1]
            if padding_length > 16:
                return "Błąd: Nieprawidłowy padding"
            decrypted = decrypted[:-padding_length]

            # Konwertuj na tekst
            return decrypted.decode('utf-8')
        except:
            return "Błąd: Nie można odszyfrować danych"

    except Exception as e:
        return f"Błąd deszyfrowania: {str(e)}"