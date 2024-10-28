# cipher_functions.py

def podstawieniowe_szyfrowanie(tekst):
    # Prosty szyfr Cezara z przesunięciem o 3
    zaszyfrowany = ""
    for char in tekst:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            zaszyfrowany += chr((ord(char) - ascii_offset + 3) % 26 + ascii_offset)
        else:
            zaszyfrowany += char
    return zaszyfrowany

def podstawieniowe_deszyfrowanie(tekst):
    # Deszyfrowanie szyfru Cezara
    odszyfrowany = ""
    for char in tekst:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            odszyfrowany += chr((ord(char) - ascii_offset - 3) % 26 + ascii_offset)
        else:
            odszyfrowany += char
    return odszyfrowany

def transpozycyjne_szyfrowanie(tekst):
    # Prosty szyfr transpozycyjny - odwrócenie tekstu
    return tekst[::-1]

def transpozycyjne_deszyfrowanie(tekst):
    # Deszyfrowanie szyfru transpozycyjnego
    return tekst[::-1]

def polialfabetyczne_szyfrowanie(tekst, klucz="KLUCZ"):
    # Prosty szyfr Vigenère'a
    zaszyfrowany = ""
    klucz = klucz.upper()
    klucz_index = 0
    for char in tekst:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shift = ord(klucz[klucz_index % len(klucz)]) - 65
            zaszyfrowany += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            klucz_index += 1
        else:
            zaszyfrowany += char
    return zaszyfrowany

def polialfabetyczne_deszyfrowanie(tekst, klucz="KLUCZ"):
    # Deszyfrowanie szyfru Vigenère'a
    odszyfrowany = ""
    klucz = klucz.upper()
    klucz_index = 0
    for char in tekst:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shift = ord(klucz[klucz_index % len(klucz)]) - 65
            odszyfrowany += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            klucz_index += 1
        else:
            odszyfrowany += char
    return odszyfrowany