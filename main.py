import os
import subprocess
import sys
import psutil
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import datetime
from datetime import datetime
from funkcje import *
import rsa

global_key_DH = ""
global_key = ""
global_public_key = ""
global_private_key = ""
class AppGUI:
    def __init__(self, master):
        self.master = master
        master.title("Aplikacja Szyfrująca")
        master.geometry("400x400")
        self.frames = []
        self.main_frame = tk.Frame(master)
        self.cipher_frame = tk.Frame(master)
        self.cipher_frame_rsa = tk.Frame(master)
        self.des_aes_frame = tk.Frame(master)
        self.transmit_frame = tk.Frame(master)
        self.transmit_frame_DH = tk.Frame(master)
        self.key_entry_frame = tk.Frame(master)
        self.rsa_frame = tk.Frame(master)
        self.key_rsa_frame = tk.Frame(master)
        self.key_DH_frame = tk.Frame(master)
        self.DH_generator = tk.Frame(master)
        self.setup_main_frame()
        self.setup_cipher_frame()
        self.setup_cipher_frame_rsa_text()
        self.setup_des_aes_frame()
        self.setup_transmit_frame()
        self.setup_transmit_frame_DH()
        self.setup_key_rsa_frame()
        self.setup_key_DH_frame()
        self.setup_rsa_frame()
        self.setup_key_entry_frame()
        self.show_main_frame()

        self.transmit_threads = []
        self.is_listening = False
        self.server_thread = None
        self.stop_event = threading.Event()

    def setup_main_frame(self):
        self.main_frame.pack(expand=True)
        label = tk.Label(self.main_frame, text="Szyfrowanie", font=("Arial", 16))
        label.pack(pady=20)
        button_frame = tk.Frame(self.main_frame)
        button_frame.pack()
        buttons = [
            ("Podstawieniowe", lambda: self.show_cipher_frame("Podstawieniowe")),
            ("Transpozycyjne", lambda: self.show_cipher_frame("Transpozycyjne")),
        ]
        for text, command in buttons:
            tk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5, pady=10)
        button_frame2 = tk.Frame(self.main_frame)
        button_frame2.pack()
        buttons2 = [
            ("DES", lambda: self.show_key_entry_frame("DES")),
            ("AES", lambda: self.show_key_entry_frame("AES")),
        ]
        for text, command in buttons2:
            tk.Button(button_frame2, text=text, command=command).pack(side=tk.LEFT, padx=5, pady=10)
        button_frame3 = tk.Frame(self.main_frame)
        button_frame3.pack()
        buttons3 = [
            ("RSA", lambda: self.show_key_rsa_frame("RSA")),
            ("DH", lambda: self.show_key_DH_frame("DH")),
            ("DH generator", lambda: self.show_DH_generator())
        ]
        for text, command in buttons3:
            tk.Button(button_frame3, text=text, command=command).pack(side=tk.LEFT, padx=5, pady=10)

    def show_DH_generator(self):
        # Ukrycie poprzednich ramek
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        self.main_frame.pack_forget()
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack_forget()
        self.key_entry_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.key_rsa_frame.pack_forget()
        self.cipher_frame_rsa.pack_forget()


        # Tworzymy pole do wpisania liczby
        number_label = tk.Label(self.main_frame, text="Podaj liczbę", font=("Arial", 12))
        number_label.pack(pady=10)

        # Pole do wprowadzenia liczby
        number_entry = tk.Entry(self.main_frame)
        number_entry.pack(pady=10)

        # Etykiety do wyświetlania kluczy
        private_key_label = tk.Label(self.main_frame, text="Prywatny klucz: ", font=("Arial", 12))
        private_key_label.pack(pady=5)

        public_key_label = tk.Label(self.main_frame, text="Publiczny klucz: ", font=("Arial", 12))
        public_key_label.pack(pady=5)

        # Funkcja do generowania kluczy z wprowadzonej liczby
        def on_generate_key():
            try:
                number = int(number_entry.get())  # Pobranie liczby z Entry
                private_key = number
                public_key = 5 ** number % 15485863

                # Aktualizowanie etykiet w GUI
                private_key_label.config(text=f"Prywatny klucz: {private_key}")
                public_key_label.config(text=f"Publiczny klucz: {public_key}")

                # Możesz także wyświetlić wygenerowane klucze w konsoli
                print(f"Prywatny klucz: {private_key}")
                print(f"Publiczny klucz: {public_key}")

            except ValueError:
                messagebox.showerror("Błąd", "Proszę wprowadzić poprawną liczbę.")

        # Przycisk generujący klucz
        self.button_gener = tk.Button(self.main_frame, text="Generuj klucz", command=on_generate_key)
        self.button_gener.pack(pady=10)

        self.main_frame.pack(padx=20, pady=20)

    def setup_key_rsa_frame(self):

        # Przycisk generowania kluczy
        self.button_gen = tk.Button(
            self.key_rsa_frame, text="Generuj klucz", command=self.generowanie_klucza_RSA
        )
        self.button_gen.pack(pady=10)

        # Pole na klucz publiczny
        key_label = tk.Label(self.key_rsa_frame, text="Wprowadź klucz publiczny:", font=("Arial", 12))
        key_label.pack(pady=10)

        self.public_key_entry_rsa = tk.Entry(self.key_rsa_frame, width=60)
        self.public_key_entry_rsa.pack(pady=5)

        # Przycisk do wczytania klucza publicznego
        def load_public_key():
            pub_file_path = filedialog.askopenfilename(
                filetypes=[("PEM files", "*.pem"), ("Text files", "*.txt")],
                title="Wybierz plik z kluczem publicznym"
            )
            if pub_file_path:
                with open(pub_file_path, "r") as pub_file:
                    public_key_data = pub_file.read()
                    self.public_key_entry_rsa.delete(0, tk.END)
                    self.public_key_entry_rsa.insert(0, public_key_data)

        self.load_public_key_button = tk.Button(self.key_rsa_frame, text="Wczytaj klucz publiczny",
                                                command=load_public_key)
        self.load_public_key_button.pack(pady=5)

        # Pole na klucz prywatny
        key_label2 = tk.Label(self.key_rsa_frame, text="Wprowadź klucz prywatny:", font=("Arial", 12))
        key_label2.pack(pady=10)

        self.private_key_entry_rsa = tk.Entry(self.key_rsa_frame, show="*", width=60)
        self.private_key_entry_rsa.pack(pady=5)

        # Przycisk do wczytania klucza prywatnego
        def load_private_key():
            priv_file_path = filedialog.askopenfilename(
                filetypes=[("PEM files", "*.pem"), ("Text files", "*.txt")],
                title="Wybierz plik z kluczem prywatnym"
            )
            if priv_file_path:
                with open(priv_file_path, "r") as priv_file:
                    private_key_data = priv_file.read()
                    self.private_key_entry_rsa.delete(0, tk.END)
                    self.private_key_entry_rsa.insert(0, private_key_data)

        self.load_private_key_button = tk.Button(self.key_rsa_frame, text="Wczytaj klucz prywatny",
                                                 command=load_private_key)
        self.load_private_key_button.pack(pady=5)

        # Przycisk do zapisania kluczy
        self.next_button = tk.Button(self.key_rsa_frame, text="Dalej", command=self.save_key_rsa_frame)
        self.next_button.pack(pady=10)

    def setup_key_DH_frame(self):
        self.button_gen.pack(pady=10)
       # Pole na klucz publiczny
        key_label = tk.Label(self.key_DH_frame, text="Wprowadź klucz publiczny:", font=("Arial", 12))
        key_label.pack(pady=10)

        self.public_key_entry = tk.Entry(self.key_DH_frame, width=60)
        self.public_key_entry.pack(pady=5)

        self.load_public_key_button.pack(pady=5)

            # Pole na klucz prywatny
        key_label2 = tk.Label(self.key_DH_frame, text="Wprowadź klucz prywatny:", font=("Arial", 12))
        key_label2.pack(pady=10)

        self.private_key_entry = tk.Entry(self.key_DH_frame, show="*", width=60)
        self.private_key_entry.pack(pady=5)

        self.load_private_key_button.pack(pady=5)

        # Przycisk do zapisania kluczy
        self.next_button = tk.Button(self.key_DH_frame, text="Dalej", command=self.save_key_DH_frame)
        self.next_button.pack(pady=10)


    def save_key_DH_frame(self):
        # Odczytywanie kluczy z pól tekstowych
        global global_key_DH, global_public_key, global_private_key
        global_public_key = self.public_key_entry.get()
        global_private_key = self.private_key_entry.get()
        print(self.public_key_entry.get(), self.private_key_entry.get())

        # Walidacja obecności przynajmniej jednego klucza
        if not global_public_key or not global_private_key:
            messagebox.showerror("Brak klucza", "Proszę podać oba klucze.")
            return

        global_key_DH = compute_shared_secret(global_public_key, global_private_key)
        # Jeśli klucze są poprawne, przejście do następnej ramki
        self.key_DH_frame.pack_forget()
        self.show_transmit_frame_DH(self.current_cipher_type)

    def generowanie_klucza_RSA(self):
        # Generowanie kluczy RSA
        (public_key, private_key) = rsa.newkeys(2048)

        # Konwersja kluczy do formatu PEM
        public_key_pem = public_key.save_pkcs1().decode('utf-8')
        private_key_pem = private_key.save_pkcs1().decode('utf-8')

        # Uzupełnienie pól klucza
        self.public_key_entry_rsa.delete(0, tk.END)
        self.public_key_entry_rsa.insert(0, public_key_pem)

        self.private_key_entry_rsa.delete(0, tk.END)
        self.private_key_entry_rsa.insert(0, private_key_pem)

        # Pobranie bieżącej daty i czasu
        current_date = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Domyślne nazwy plików z datą i czasem
        default_public_filename = f"public_key_{current_date}.pem"
        default_private_filename = f"private_key_{current_date}.pem"

        # Wyświetlenie okna dialogowego do zapisu klucza publicznego z domyślną nazwą pliku
        pub_file_path = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem")],
            title="Zapisz klucz publiczny",
            initialfile=default_public_filename
        )
        if pub_file_path:
            with open(pub_file_path, "w") as pub_file:
                pub_file.write(public_key_pem)

        # Wyświetlenie okna dialogowego do zapisu klucza prywatnego z domyślną nazwą pliku
        priv_file_path = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem")],
            title="Zapisz klucz prywatny",
            initialfile=default_private_filename
        )
        if priv_file_path:
            with open(priv_file_path, "w") as priv_file:
                priv_file.write(private_key_pem)

        messagebox.showinfo("Sukces", "Klucze zostały wygenerowane i zapisane do plików.")

    def save_key_rsa_frame(self):
        # Odczytywanie kluczy z pól tekstowych RSA
        global global_public_key, global_private_key
        global_public_key = self.public_key_entry_rsa.get()
        global_private_key = self.private_key_entry_rsa.get()
        print(self.public_key_entry_rsa.get(), self.private_key_entry_rsa.get())

        # Walidacja obecności przynajmniej jednego klucza
        if not global_public_key and not global_private_key:
            messagebox.showerror("Brak klucza", "Proszę podać przynajmniej jeden klucz.")
            return

        # Walidacja poprawności klucza publicznego
        if global_public_key:
            try:
                rsa.PublicKey.load_pkcs1(global_public_key.encode('utf-8'))
            except ValueError:
                messagebox.showerror("Błąd klucza", "Podany klucz publiczny jest nieprawidłowy.")
                return

        # Walidacja poprawności klucza prywatnego
        if global_private_key:
            try:
                rsa.PrivateKey.load_pkcs1(global_private_key.encode('utf-8'))
            except ValueError:
                messagebox.showerror("Błąd klucza", "Podany klucz prywatny jest nieprawidłowy.")
                return

        # Jeśli klucze są poprawne, przejście do następnej ramki
        self.key_rsa_frame.pack_forget()
        self.show_rsa_frame(self.current_cipher_type)

    def setup_key_entry_frame(self):
        self.add_back_button(self.key_entry_frame)
        key_label = tk.Label(self.key_entry_frame, text="Wprowadź klucz:", font=("Arial", 12))
        key_label.pack(pady=10)
        self.key_entry = tk.Entry(self.key_entry_frame, show='*', width=40)
        self.key_entry.pack(pady=5)
        self.show_key_button = tk.Button(self.key_entry_frame, text="Pokaż klucz", command=self.toggle_key_visibility)
        self.show_key_button.pack(pady=5)
        self.next_button = tk.Button(self.key_entry_frame, text="Dalej", command=self.save_key_and_show_des_aes_frame)
        self.next_button.pack(pady=10)

    def save_key_and_show_des_aes_frame(self):
        global global_key
        global_key = self.key_entry.get()
        if self.current_cipher_type == "DES":
            if len(global_key) != 8:
                messagebox.showerror("Błąd klucza", "Klucz DES musi mieć 8 znaków.")
                return
        if not global_key:
            messagebox.showerror("Brak klucza", "Proszę podać klucz.")
            return
        print(global_key)
        self.key_entry_frame.pack_forget()
        self.show_des_aes_frame(self.current_cipher_type)

    def toggle_key_visibility(self):
        if self.key_entry.cget('show') == '*':
            self.key_entry.config(show='')
            self.show_key_button.config(text="Ukryj klucz")
        else:
            self.key_entry.config(show='*')
            self.show_key_button.config(text="Pokaż klucz")

    def show_file_encryption_rsa(self):
        for widget in self.key_rsa_frame.winfo_children():
            widget.destroy()


        # Inicjalizacja zmiennych przed użyciem
        print(self.public_key_entry)
        print(self.private_key_entry)
        # Sprawdzamy, czy widgety public_key_entry i private_key_entry istnieją
        has_public_key = bool(global_public_key)

        has_private_key = bool(global_private_key)

        # Dodanie widżetów do ramki
        self.file_label = tk.Label(self.key_rsa_frame, text="Wybrany plik: ")
        self.file_label.pack(pady=10)

        file_button = tk.Button(self.key_rsa_frame, text="Wybierz plik", command=self.select_file)
        file_button.pack(pady=5)

        button_frame = tk.Frame(self.key_rsa_frame)
        button_frame.pack(pady=10)
        print(has_public_key)
        print(has_private_key)
        # Wyświetlenie odpowiednich przycisków w zależności od dostępności kluczy
        if has_public_key:
            encrypt_button = tk.Button(button_frame, text="Szyfruj", command=self.encrypt_file)
            encrypt_button.pack(side=tk.LEFT, padx=20)
        if has_private_key:
            decrypt_button = tk.Button(button_frame, text="Deszyfruj", command=self.decrypt_file)
            decrypt_button.pack(side=tk.RIGHT, padx=20)

    def setup_cipher_frame(self):
        self.add_back_button(self.cipher_frame)
        self.cipher_type_label = tk.Label(self.cipher_frame, text="", font=("Arial", 14))
        self.cipher_type_label.pack(pady=10)
        input_frame = tk.Frame(self.cipher_frame)
        input_frame.pack(pady=10)
        tk.Label(input_frame, text="Tekst do zaszyfrowania/odszyfrowania:").pack()
        self.text_input_text = tk.Text(input_frame, height=5, width=40)
        self.text_input_text.pack()
        file_button_frame = tk.Frame(input_frame)
        file_button_frame.pack(pady=5)
        tk.Button(file_button_frame, text="Wybierz plik", command=self.load_file).pack(side=tk.LEFT, padx=5)
        tk.Button(file_button_frame, text="Zapisz do pliku", command=self.save_file).pack(side=tk.LEFT, padx=5)
        button_frame = tk.Frame(self.cipher_frame)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Szyfrowanie", command=lambda: self.process_text("szyfrowanie")).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Odszyfrowywanie", command=lambda: self.process_text("odszyfrowywanie")).pack(side=tk.LEFT, padx=5)
        self.cipher_result_text = scrolledtext.ScrolledText(self.cipher_frame, height=5, width=40, wrap=tk.WORD)
        self.cipher_result_text.pack(pady=10)
        self.cipher_result_text.config(state=tk.DISABLED)



    def setup_rsa_frame(self):
        self.rsa_frame = tk.Label(self.rsa_frame, text="", font=("Arial", 14))
        self.rsa_frame.pack(pady=10)
        print("setup")
        button_frame = tk.Frame(self.rsa_frame)
        button_frame.pack(pady=10)
        buttons = [
            ("Tekst", self.show_text_encryption_rsa),
            ("Plik", self.show_file_encryption_rsa),

        ]
        for text, command in buttons:
            tk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)

    def setup_des_aes_frame(self):
        self.add_back_button(self.des_aes_frame)
        self.des_aes_label = tk.Label(self.des_aes_frame, text="", font=("Arial", 14))
        self.des_aes_label.pack(pady=10)
        button_frame = tk.Frame(self.des_aes_frame)
        button_frame.pack(pady=10)
        buttons = [
            ("Tekst", self.show_text_encryption),
            ("Plik", self.show_file_encryption),
            ("Transmituj", self.show_transmit_frame)
        ]
        for text, command in buttons:
            tk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)

    def setup_transmit_frame(self):
        self.add_back_button(self.transmit_frame)

        # Ramka dla adresu IP i portu
        ip_frame_aes = tk.Frame(self.transmit_frame)
        ip_frame_aes.pack(pady=10)

        # Pole adresu IP
        tk.Label(ip_frame_aes, text="Adres IP:").pack(side=tk.LEFT)
        self.ip_entry_aes = tk.Entry(ip_frame_aes, width=15)
        self.ip_entry_aes.pack(side=tk.LEFT, padx=5)
        self.ip_entry_aes.insert(0, "127.0.0.1")  # Domyślny adres

        # Pole portu
        tk.Label(ip_frame_aes, text="Port:").pack(side=tk.LEFT)
        self.port_entry_aes = tk.Entry(ip_frame_aes, width=6)
        self.port_entry_aes.pack(side=tk.LEFT, padx=5)
        self.port_entry_aes.insert(0, "12345")  # Domyślny port

        # Przycisk do rozpoczęcia/zatrzymania nasłuchiwania
        self.listen_button_aes = tk.Button(self.transmit_frame,
                                       text="Start nasłuchiwania",
                                       command=self.toggle_listening)
        self.listen_button_aes.pack(pady=5)

        # Pole tekstowe do wprowadzania wiadomości
        self.text_input_aes = scrolledtext.ScrolledText(self.transmit_frame,
                                                    height=5,
                                                    width=40,
                                                    wrap=tk.WORD)
        self.text_input_aes.pack(pady=10)

        # Pole do wyświetlania wiadomości przychodzących
        self.received_messages_aes = scrolledtext.ScrolledText(self.transmit_frame,
                                                           height=10,
                                                           width=40,
                                                           wrap=tk.WORD)
        self.received_messages_aes.pack(pady=10)
        self.received_messages_aes.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
        self.text_input_aes.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
        # Powiązanie zdarzenia KeyRelease z funkcją wysyłania wiadomości
        self.text_input_aes.bind("<KeyRelease>", self.send_message_event)

        # Pole do wyświetlania statusu
        self.status_label_aes = tk.Label(self.transmit_frame, text="")
        self.status_label_aes.pack(pady=5)

        self.is_listening = False
        self.server_thread = None

    def setup_transmit_frame_DH(self):
        self.add_back_button(self.transmit_frame_DH)

        # Ramka dla adresu IP i portu
        ip_frame = tk.Frame(self.transmit_frame_DH)
        ip_frame.pack(pady=10)

        # Pole adresu IP
        tk.Label(ip_frame, text="Adres IP:").pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(ip_frame, width=15)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.ip_entry.insert(0, "127.0.0.1")  # Domyślny adres

        # Pole portu
        tk.Label(ip_frame, text="Port:").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(ip_frame, width=6)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_entry.insert(0, "12345")  # Domyślny port

        # Przycisk do rozpoczęcia/zatrzymania nasłuchiwania
        self.listen_button = tk.Button(self.transmit_frame_DH,
                                       text="Start nasłuchiwania",
                                       command=self.toggle_listening_DH)
        self.listen_button.pack(pady=5)

        # Pole tekstowe do wprowadzania wiadomości
        self.text_input = scrolledtext.ScrolledText(self.transmit_frame_DH,
                                                    height=5,
                                                    width=40,
                                                    wrap=tk.WORD)
        self.text_input.pack(pady=10)

        # Pole do wyświetlania wiadomości przychodzących
        self.received_messages = scrolledtext.ScrolledText(self.transmit_frame_DH,
                                                           height=10,
                                                           width=40,
                                                           wrap=tk.WORD)
        self.received_messages.pack(pady=10)
        self.received_messages.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
        self.text_input.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
        # Powiązanie zdarzenia KeyRelease z funkcją wysyłania wiadomości
        self.text_input.bind("<KeyRelease>", self.send_message_event_DH)

        # Pole do wyświetlania statusu
        self.status_label = tk.Label(self.transmit_frame, text="")
        self.status_label.pack(pady=5)

        self.is_listening = False
        self.server_thread = None

    def send_message(self):
        global global_key
        try:
            address = self.ip_entry_aes.get()
            port = int(self.port_entry_aes.get())
            text = self.text_input_aes.get("1.0", tk.END).strip()
            current_cipher_type = self.current_cipher_type
            if text:
                if send_text(address, port, text, current_cipher_type, global_key):
                    self.status_label_aes.config(text="Wiadomość wysłana")
                else:
                    self.status_label_aes.config(text="Błąd wysyłania")
        except Exception as e:
            messagebox.showerror("Błąd", f"Błąd podczas wysyłania: {e}")

    def send_message_DH(self):
        global global_public_key, global_private_key
        try:
            address = self.ip_entry.get()
            port = int(self.port_entry.get())
            text = self.text_input.get("1.0", tk.END).strip()
            current_cipher_type = self.current_cipher_type
            if text:
                if send_text_DH(address, port, text, current_cipher_type, global_key_DH):
                    self.status_label.config(text="Wiadomość wysłana")
                else:
                    self.status_label.config(text="Błąd wysyłania")
        except Exception as e:
            messagebox.showerror("Błąd", f"Błąd podczas wysyłania: {e}")


    def send_message_event(self, event):
        self.send_message()  # Wywołaj funkcję wysyłania wiadomości

    def send_message_event_DH(self, event):
        self.send_message_DH()  # Wywołaj funkcję wysyłania wiadomości

    def display_received_message_DH(self, message):
        self.received_messages.config(state=tk.NORMAL)  # Umożliwienie edycji
        self.received_messages.delete("1.0", tk.END)
        self.received_messages.insert(tk.END, message + "\n")  # Dodaj wiadomość
        self.received_messages.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
        self.received_messages.yview(tk.END)  # Przewiń do końca

    def display_received_message(self, message):
        self.received_messages_aes.config(state=tk.NORMAL)  # Umożliwienie edycji
        self.received_messages_aes.delete("1.0", tk.END)
        self.received_messages_aes.insert(tk.END, message + "\n")  # Dodaj wiadomość
        self.received_messages_aes.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
        self.received_messages_aes.yview(tk.END)  # Przewiń do końca


    def toggle_listening(self):
        global global_key
        if not self.is_listening:
            try:
                address = self.ip_entry_aes.get()
                port = int(self.port_entry_aes.get())
                self.stop_event.clear()  # Resetujemy flagę

                # Uruchom serwer w nowym wątku, przekazując funkcję do wyświetlania wiadomości
                self.server_thread = threading.Thread(target=receive_text, args=(
                address, port, self.stop_event, self.display_received_message, self.current_cipher_type, global_key))
                self.server_thread.daemon = True
                self.server_thread.start()
                self.text_input_aes.config(state=tk.NORMAL)  # Umożliwienie edycji
                self.is_listening = True
                self.listen_button_aes.config(text="Stop nasłuchiwania")
                self.status_label_aes.config(text=f"Nasłuchiwanie na {address}:{port}")
            except Exception as e:
                messagebox.showerror("Błąd", f"Nie można uruchomić nasłuchiwania: {e}")
        else:
            # Ustaw flagę zatrzymania
            print("Zatrzymywanie serwera...")
            self.stop_event.set()
            self.is_listening = False

            self.text_input_aes.delete("1.0", tk.END)
            self.text_input_aes.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
            self.received_messages_aes.config(state=tk.NORMAL)  # Umożliwienie edycji
            self.received_messages_aes.delete("1.0", tk.END)
            self.received_messages_aes.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
            self.listen_button_aes.config(text="Start nasłuchiwania")
            self.status_label_aes.config(text="Nasłuchiwanie zatrzymane")

    def toggle_listening_DH(self):
        global global_public_key, global_private_key
        if not self.is_listening:
            try:
                address = self.ip_entry.get()
                port = int(self.port_entry.get())
                self.stop_event.clear()  # Resetujemy flagę

                # Uruchom serwer w nowym wątku, przekazując funkcję do wyświetlania wiadomości
                self.server_thread = threading.Thread(target=receive_text_DH, args=(
                address, port, self.stop_event, self.display_received_message_DH, self.current_cipher_type, global_key_DH))
                self.server_thread.daemon = True
                self.server_thread.start()
                self.text_input.config(state=tk.NORMAL)  # Umożliwienie edycji
                self.is_listening = True
                self.listen_button.config(text="Stop nasłuchiwania")
                self.status_label.config(text=f"Nasłuchiwanie na {address}:{port}")
            except Exception as e:
                messagebox.showerror("Błąd", f"Nie można uruchomić nasłuchiwania: {e}")
        else:
            # Ustaw flagę zatrzymania
            print("Zatrzymywanie serwera...")
            self.stop_event.set()
            self.is_listening = False

            self.text_input.delete("1.0", tk.END)
            self.text_input.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
            self.received_messages.config(state=tk.NORMAL)  # Umożliwienie edycji
            self.received_messages.delete("1.0", tk.END)
            self.received_messages.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
            self.listen_button.config(text="Start nasłuchiwania")
            self.status_label.config(text="Nasłuchiwanie zatrzymane")

    def show_transmit_frame(self):
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack(fill=tk.BOTH, expand=True)

    def show_transmit_frame_DH(self, current_cipher_type):
        self.des_aes_frame.pack_forget()
        self.transmit_frame_DH.pack(fill=tk.BOTH, expand=True)

    def add_back_button(self, frame):
        back_button = tk.Button(frame, text="←", command=self.show_main_frame)
        back_button.pack(anchor="nw", padx=10, pady=10)

    def show_main_frame(self):
        self.cipher_frame.pack_forget()
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack_forget()
        self.key_entry_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.key_rsa_frame.pack_forget()
        self.cipher_frame_rsa.pack_forget()
        self.cipher_frame.pack_forget()
        self.cipher_frame_rsa.pack_forget()
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack_forget()
        self.key_entry_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.key_rsa_frame.pack_forget()
        self.cipher_frame.pack_forget()
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack_forget()
        self.key_entry_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.key_rsa_frame.pack_forget()
        for frame in self.frames:
            frame.pack_forget()
        # Resetowanie kluczy
        global global_public_key, global_private_key
        global_public_key = ""
        global_private_key = ""

        self.text_input.delete('1.0', tk.END)
        self.text_input_text.delete('1.0', tk.END)# Wyczyść pole do wprowadzania tekstu
        self.cipher_result_text.config(state=tk.NORMAL)
        self.cipher_result_text.delete('1.0', tk.END)  # Wyczyść wyniki szyfrowania/odszyfrowania
        self.cipher_result_text.config(state=tk.DISABLED)
        self.key_entry.delete(0, tk.END)  # Wyczyść pole do wprowadzania klucza
        self.main_frame.pack(expand=True)

    def show_cipher_frame_rsa(self, cipher_type):
        # Ukrycie poprzednich ramek
        for widget in self.key_rsa_frame.winfo_children():
            widget.destroy()
        self.main_frame.pack_forget()
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack_forget()
        self.key_entry_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.key_rsa_frame.pack_forget()
        self.cipher_frame_rsa.pack_forget()

        self.add_back_button(self.key_rsa_frame)

        # Ramka wejściowa dla tekstu do szyfrowania/odszyfrowywania
        input_frame = tk.Frame(self.key_rsa_frame)
        input_frame.pack(pady=10)

        tk.Label(input_frame, text="Tekst do zaszyfrowania/odszyfrowania:").pack()
        self.text_input_text = tk.Text(input_frame, height=5, width=40)
        self.text_input_text.pack()

        # Ramka na przyciski do wyboru pliku
        file_button_frame = tk.Frame(input_frame)
        file_button_frame.pack(pady=5)

        tk.Button(file_button_frame, text="Wybierz plik", command=self.load_file).pack(side=tk.LEFT, padx=5)
        tk.Button(file_button_frame, text="Zapisz do pliku", command=self.save_file).pack(side=tk.LEFT, padx=5)

        # Ramka na przyciski szyfrowania/deszyfrowania
        button_frame = tk.Frame(self.key_rsa_frame)
        button_frame.pack(pady=10)

        # Sprawdzanie dostępności kluczy
        has_public_key = bool(global_public_key)
        has_private_key = bool(global_private_key)

        if has_public_key:
            tk.Button(button_frame, text="Szyfrowanie", command=lambda: self.process_text_rsa("szyfrowanie")).pack(
                side=tk.LEFT, padx=5)

        if has_private_key:
            tk.Button(button_frame, text="Odszyfrowywanie", command=lambda: self.process_text_rsa("odszyfrowywanie")).pack(
                side=tk.LEFT, padx=5)

        # Ramka na wynik szyfrowania/odszyfrowywania
        self.cipher_result_text = scrolledtext.ScrolledText(self.key_rsa_frame, height=5, width=40, wrap=tk.WORD)
        self.cipher_result_text.pack(pady=10)
        self.cipher_result_text.config(state=tk.DISABLED)

        # Aktywowanie ramki key_rsa_frame
        self.key_rsa_frame.pack(fill=tk.BOTH, expand=True)

    def show_cipher_frame(self, cipher_type):
        self.main_frame.pack_forget()
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack_forget()
        self.key_entry_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.cipher_frame.pack(fill=tk.BOTH, expand=True)
        self.cipher_type_label.config(text=f"Szyfrowanie {cipher_type}")
        self.current_cipher_type = cipher_type
        self.cipher_result_text.config(state=tk.NORMAL)
        self.cipher_result_text.delete('1.0', tk.END)
        self.cipher_result_text.config(state=tk.DISABLED)

    def show_key_rsa_frame(self, cipher_type):
        self.current_cipher_type = cipher_type
        print(self.current_cipher_type)
        self.main_frame.pack_forget()
        self.key_rsa_frame.pack(fill=tk.BOTH, expand=True)
        self.public_key_entry.delete(0, tk.END)
        self.private_key_entry.delete(0, tk.END)

    def show_key_DH_frame(self, cipher_type):
        self.current_cipher_type = cipher_type
        print(self.current_cipher_type)
        self.main_frame.pack_forget()
        self.key_DH_frame.pack(fill=tk.BOTH, expand=True)
        self.public_key_entry.delete(0, tk.END)
        self.private_key_entry.delete(0, tk.END)
    def show_key_entry_frame(self, cipher_type):
        self.current_cipher_type = cipher_type
        self.main_frame.pack_forget()
        self.key_entry_frame.pack(fill=tk.BOTH, expand=True)

    def show_rsa_frame(self, cipher_type):
        self.current_cipher_type = cipher_type
        self.main_frame.pack_forget()
        self.rsa_frame.pack_forget()
        self.transmit_frame.pack_forget()

        for widget in self.key_rsa_frame.winfo_children():
            widget.destroy()
        self.rsa_label = tk.Label(self.key_rsa_frame, text=f"Szyfruj/deszyfruj {cipher_type}")
        self.rsa_label.pack(pady=10)

        button_frame = tk.Frame(self.key_rsa_frame)
        button_frame.pack(pady=10)

        buttons = [
            ("Tekst", self.show_text_encryption_rsa),
            ("Plik", self.show_file_encryption_rsa),
        ]

        for text, command in buttons:
            # Upewnij się, że metoda 'command' jest prawidłowo przypisana
            button = tk.Button(button_frame, text=text, command=command)
            button.pack(side=tk.LEFT, padx=5)

        # Po dodaniu przycisków wyświetlamy ramkę
        self.key_rsa_frame.pack(fill=tk.BOTH, expand=True)

    def show_des_aes_frame(self, cipher_type):
        for widget in self.des_aes_frame.winfo_children():
            widget.destroy()
        self.des_aes_label = tk.Label(self.des_aes_frame, text=f"Szyfruj/deszyfruj {cipher_type}")
        self.des_aes_label.pack(pady=10)
        button_frame = tk.Frame(self.des_aes_frame)
        button_frame.pack(pady=10)
        buttons = [
            ("Tekst", self.show_text_encryption),
            ("Plik", self.show_file_encryption),
            ("Transmituj", self.show_transmit_frame)
        ]
        for text, command in buttons:
            tk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)
        self.des_aes_frame.pack(fill=tk.BOTH, expand=True)

    def show_transmit_frame(self):
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack(fill=tk.BOTH, expand=True)

    def show_text_encryption_rsa(self):
        self.show_cipher_frame_rsa(self.current_cipher_type)
        print(self.current_cipher_type)
    def show_text_encryption(self):
        self.show_cipher_frame(self.current_cipher_type)

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Pliki tekstowe", "*.txt")])
        if file_path:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                self.text_input_text.delete('1.0', tk.END)
                self.text_input_text.insert(tk.END, content)

    def save_file(self):
        content = self.cipher_result_text.get('1.0', tk.END).strip()
        if content:
            current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.current_cipher_type}_{current_time}.txt"
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=filename, filetypes=[("Pliki tekstowe", "*.txt")])
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(content)
                tk.messagebox.showinfo("Zapisano", f"Plik został zapisany jako {file_path}")
        else:
            tk.messagebox.showwarning("Brak danych", "Brak danych do zapisania.")

    def process_text_rsa(self, action):
        global global_public_key
        global global_private_key
        text = self.text_input_text.get('1.0', tk.END).strip()
        key_public = global_public_key
        key_private = global_private_key
        print(text)
        if text:
            if  self.current_cipher_type == "RSA":
                if not key_public and not key_private:
                    messagebox.showerror("Brak klucza", "Proszę podać klucz.")
                    return
                if action == "szyfrowanie":
                    result = rsa_szyfrowanie(text, global_public_key)
                else:
                    result = rsa_deszyfrowanie(text, global_private_key)

            self.cipher_result_text.config(state=tk.NORMAL)
            self.cipher_result_text.delete('1.0', tk.END)
            self.cipher_result_text.insert(tk.END, result)
            self.cipher_result_text.config(state=tk.DISABLED)
        else:
            self.cipher_result_text.config(state=tk.NORMAL)
            self.cipher_result_text.delete('1.0', tk.END)
            self.cipher_result_text.insert(tk.END, "Proszę wprowadzić tekst lub wybrać plik.")
            self.cipher_result_text.config(state=tk.DISABLED)

    def process_text(self, action):
        text = self.text_input_text.get('1.0', tk.END).strip()
        key = global_key
        print(text)
        if text:
            if self.current_cipher_type == "Podstawieniowe":
                if action == "szyfrowanie":
                    result = podstawieniowe_szyfrowanie(text)
                else:
                    result = podstawieniowe_deszyfrowanie(text)
            elif self.current_cipher_type == "Transpozycyjne":
                if action == "szyfrowanie":
                    result = transpozycyjne_szyfrowanie(text)
                else:
                    result = transpozycyjne_deszyfrowanie(text)
            elif self.current_cipher_type == "DES":
                if not key:
                    messagebox.showerror("Brak klucza", "Proszę podać klucz.")
                    return
                if action == "szyfrowanie":
                    result = des_szyfrowanie(text, global_key)
                else:
                    result = des_deszyfrowanie(text, global_key)
            elif self.current_cipher_type == "AES":
                if not key:
                    messagebox.showerror("Brak klucza", "Proszę podać klucz.")
                    return
                if action == "szyfrowanie":
                    result = aes_szyfrowanie(text, global_key)
                else:
                    result = aes_deszyfrowanie(text, global_key)
            self.cipher_result_text.config(state=tk.NORMAL)
            self.cipher_result_text.delete('1.0', tk.END)
            self.cipher_result_text.insert(tk.END, result)
            self.cipher_result_text.config(state=tk.DISABLED)
        else:
            self.cipher_result_text.config(state=tk.NORMAL)
            self.cipher_result_text.delete('1.0', tk.END)
            self.cipher_result_text.insert(tk.END, "Proszę wprowadzić tekst lub wybrać plik.")
            self.cipher_result_text.config(state=tk.DISABLED)

    def setup_cipher_frame_rsa_text(self):
        # Sprawdzenie, czy public_key_entry i private_key_entry są już zainicjowane
        if hasattr(self, 'public_key_entry') and hasattr(self, 'private_key_entry'):
            has_public_key = bool(self.public_key_entry.get())
            has_private_key = bool(self.private_key_entry.get())
        else:
            # W przypadku, gdyby klucze nie były zainicjowane
            has_public_key = False
            has_private_key = False

        self.cipher_type_label = tk.Label(self.cipher_frame, text="", font=("Arial", 14))
        self.cipher_type_label.pack(pady=10)

        input_frame = tk.Frame(self.cipher_frame)
        input_frame.pack(pady=10)

        tk.Label(input_frame, text="Tekst do zaszyfrowania/odszyfrowania:").pack()
        self.text_input_text = tk.Text(input_frame, height=5, width=40)
        self.text_input_text.pack()

        file_button_frame = tk.Frame(input_frame)
        file_button_frame.pack(pady=5)
        tk.Button(file_button_frame, text="Wybierz plik", command=self.load_file).pack(side=tk.LEFT, padx=5)
        tk.Button(file_button_frame, text="Zapisz do pliku", command=self.save_file).pack(side=tk.LEFT, padx=5)

        button_frame = tk.Frame(self.cipher_frame)
        button_frame.pack(pady=10)

        # Wyświetlanie przycisków w zależności od dostępnych kluczy
        if has_public_key:
            self.encrypt_button = tk.Button(
                button_frame, text="Szyfrowanie", command=lambda: self.process_text_rsa("szyfrowanie")
            )
            self.encrypt_button.pack(side=tk.LEFT, padx=5)

        if has_private_key:
            self.decrypt_button = tk.Button(
                button_frame, text="Odszyfrowywanie", command=lambda: self.process_text_rsa("odszyfrowywanie")
            )
            self.decrypt_button.pack(side=tk.LEFT, padx=5)

        self.cipher_result_text = scrolledtext.ScrolledText(self.cipher_frame, height=5, width=40, wrap=tk.WORD)
        self.cipher_result_text.pack(pady=10)
        self.cipher_result_text.config(state=tk.DISABLED)

    def show_file_encryption(self):
        for widget in self.des_aes_frame.winfo_children():
            widget.destroy()
        self.add_back_button(self.des_aes_frame)
        self.file_label = tk.Label(self.des_aes_frame, text="Wybrany plik: ")
        self.file_label.pack(pady=10)
        file_button = tk.Button(self.des_aes_frame, text="Wybierz plik", command=self.select_file)
        file_button.pack(pady=5)
        encrypt_button = tk.Button(self.des_aes_frame, text="Szyfruj", command=self.encrypt_file)
        encrypt_button.pack(side=tk.LEFT, padx=20, pady=10)
        decrypt_button = tk.Button(self.des_aes_frame, text="Deszyfruj", command=self.decrypt_file)
        decrypt_button.pack(side=tk.RIGHT, padx=20, pady=10)
        self.des_aes_frame.pack(fill=tk.BOTH, expand=True)

    def select_file(self):
        file_path = filedialog.askopenfilename(title="Wybierz plik do zaszyfrowania/odszyfrowania")
        if file_path:
            self.file_label.config(text=f"Wybrany plik: {file_path}")

    def encrypt_file(self):
        file_path = self.file_label.cget("text").replace("Wybrany plik: ", "")
        if file_path:
            try:
                if self.current_cipher_type == "DES":
                    result = des_szyfrowanie_plik(file_path, global_key)
                elif self.current_cipher_type == "AES":
                    result = aes_szyfrowanie_plik(file_path, global_key)
                elif self.current_cipher_type == "RSA":
                    result = rsa_szyfrowanie_plik(file_path, global_public_key)
                messagebox.showinfo("Sukces", "Plik został zaszyfrowany pomyślnie.")
            except Exception as e:
                messagebox.showerror("Błąd", f"Wystąpił błąd podczas szyfrowania: {str(e)}")
        else:
            messagebox.showerror("Błąd", "Proszę wybrać plik.")


    def decrypt_file(self):
        file_path = self.file_label.cget("text").replace("Wybrany plik: ", "")
        if file_path:
            try:
                if self.current_cipher_type == "DES":
                    result = des_deszyfrowanie_plik(file_path, global_key)
                elif self.current_cipher_type == "AES":
                    result = aes_deszyfrowanie_plik(file_path, global_key)
                elif self.current_cipher_type == "RSA":
                    result = rsa_deszyfrowanie_plik(file_path, global_private_key)
                messagebox.showinfo("Sukces", "Plik został odszyfrowany pomyślnie.")
            except Exception as e:
                messagebox.showerror("Błąd", f"Wystąpił błąd podczas deszyfrowania: {str(e)}")
        else:
            messagebox.showerror("Błąd", "Proszę wybrać plik.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AppGUI(root)
    root.mainloop()