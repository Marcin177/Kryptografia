import tkinter as tk
from tkinter import scrolledtext, messagebox
import datetime
from funkcje import *

global_key = ""

class AppGUI:
    def __init__(self, master):
        self.master = master
        master.title("Aplikacja Szyfrująca")
        master.geometry("400x400")
        self.main_frame = tk.Frame(master)
        self.cipher_frame = tk.Frame(master)
        self.des_aes_frame = tk.Frame(master)
        self.transmit_frame = tk.Frame(master)
        self.key_entry_frame = tk.Frame(master)
        self.setup_main_frame()
        self.setup_cipher_frame()
        self.setup_des_aes_frame()
        self.setup_transmit_frame()
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
        ip_frame = tk.Frame(self.transmit_frame)
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
        self.listen_button = tk.Button(self.transmit_frame,
                                       text="Start nasłuchiwania",
                                       command=self.toggle_listening)
        self.listen_button.pack(pady=5)

        # Pole tekstowe do wprowadzania wiadomości
        self.text_input = scrolledtext.ScrolledText(self.transmit_frame,
                                                    height=5,
                                                    width=40,
                                                    wrap=tk.WORD)
        self.text_input.pack(pady=10)

        # Pole do wyświetlania wiadomości przychodzących
        self.received_messages = scrolledtext.ScrolledText(self.transmit_frame,
                                                           height=10,
                                                           width=40,
                                                           wrap=tk.WORD)
        self.received_messages.pack(pady=10)
        self.received_messages.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
        self.text_input.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
        # Powiązanie zdarzenia KeyRelease z funkcją wysyłania wiadomości
        self.text_input.bind("<KeyRelease>", self.send_message_event)

        # Pole do wyświetlania statusu
        self.status_label = tk.Label(self.transmit_frame, text="")
        self.status_label.pack(pady=5)

        self.is_listening = False
        self.server_thread = None

    def send_message(self):
        global global_key
        try:
            address = self.ip_entry.get()
            port = int(self.port_entry.get())
            text = self.text_input.get("1.0", tk.END).strip()
            current_cipher_type = self.current_cipher_type
            if text:
                if send_text(address, port, text, current_cipher_type, global_key):
                    self.status_label.config(text="Wiadomość wysłana")
                else:
                    self.status_label.config(text="Błąd wysyłania")
        except Exception as e:
            messagebox.showerror("Błąd", f"Błąd podczas wysyłania: {e}")


    def send_message_event(self, event):
        self.send_message()  # Wywołaj funkcję wysyłania wiadomości

    def display_received_message(self, message):
        self.received_messages.config(state=tk.NORMAL)  # Umożliwienie edycji
        self.received_messages.delete("1.0", tk.END)
        self.received_messages.insert(tk.END, message + "\n")  # Dodaj wiadomość
        self.received_messages.config(state=tk.DISABLED)  # Ustaw na tylko do odczytu
        self.received_messages.yview(tk.END)  # Przewiń do końca

    def toggle_listening(self):
        global global_key
        if not self.is_listening:
            try:
                address = self.ip_entry.get()
                port = int(self.port_entry.get())
                self.stop_event.clear()  # Resetujemy flagę

                # Uruchom serwer w nowym wątku, przekazując funkcję do wyświetlania wiadomości
                self.server_thread = threading.Thread(target=receive_text, args=(
                address, port, self.stop_event, self.display_received_message, self.current_cipher_type, global_key))
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

    def handle_text_change(self, event):
        # Get the IP and port, and send each character typed
        target_ip = self.ip_entry.get()
        target_port = 12345  # Replace with desired port

        if target_ip:
            text = self.text_input.get("1.0", tk.END).strip()
            if self.transmit_threads:
                send_text(target_ip, target_port, text)
            else:
                # Initialize the receive thread only once per session
                self.start_transmit(target_ip, target_port)

    def start_transmit(self, target_ip, target_port):
        # Start receiving thread
        receive_thread = threading.Thread(target=receive_text, args=(
                target_ip, target_port, self.stop_event, self.display_received_message, self.current_cipher_type, global_key))
        receive_thread.daemon = True
        receive_thread.start()
        self.transmit_threads.append(receive_thread)

    def show_transmit_frame(self):
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack(fill=tk.BOTH, expand=True)

    def add_back_button(self, frame):
        back_button = tk.Button(frame, text="←", command=self.show_main_frame)
        back_button.pack(anchor="nw", padx=10, pady=10)

    def show_main_frame(self):
        self.cipher_frame.pack_forget()
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack_forget()
        self.key_entry_frame.pack_forget()
        self.text_input.delete('1.0', tk.END)
        self.text_input_text.delete('1.0', tk.END)# Wyczyść pole do wprowadzania tekstu
        self.cipher_result_text.config(state=tk.NORMAL)
        self.cipher_result_text.delete('1.0', tk.END)  # Wyczyść wyniki szyfrowania/odszyfrowania
        self.cipher_result_text.config(state=tk.DISABLED)
        self.key_entry.delete(0, tk.END)  # Wyczyść pole do wprowadzania klucza
        self.main_frame.pack(expand=True)

    def show_cipher_frame(self, cipher_type):
        self.main_frame.pack_forget()
        self.des_aes_frame.pack_forget()
        self.transmit_frame.pack_forget()
        self.cipher_frame.pack(fill=tk.BOTH, expand=True)
        self.cipher_type_label.config(text=f"Szyfrowanie {cipher_type}")
        self.current_cipher_type = cipher_type
        self.cipher_result_text.config(state=tk.NORMAL)
        self.cipher_result_text.delete('1.0', tk.END)
        self.cipher_result_text.config(state=tk.DISABLED)

    def show_key_entry_frame(self, cipher_type):
        self.current_cipher_type = cipher_type
        self.main_frame.pack_forget()
        self.key_entry_frame.pack(fill=tk.BOTH, expand=True)

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
            print(result)
            self.cipher_result_text.config(state=tk.NORMAL)
            self.cipher_result_text.delete('1.0', tk.END)
            self.cipher_result_text.insert(tk.END, result)
            self.cipher_result_text.config(state=tk.DISABLED)
        else:
            self.cipher_result_text.config(state=tk.NORMAL)
            self.cipher_result_text.delete('1.0', tk.END)
            self.cipher_result_text.insert(tk.END, "Proszę wprowadzić tekst lub wybrać plik.")
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
                messagebox.showinfo("Sukces", "Plik został odszyfrowany pomyślnie.")
            except Exception as e:
                messagebox.showerror("Błąd", f"Wystąpił błąd podczas deszyfrowania: {str(e)}")
        else:
            messagebox.showerror("Błąd", "Proszę wybrać plik.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AppGUI(root)
    root.mainloop()