import tkinter as tk
from tkinter import filedialog, scrolledtext
from funkcje import *


class AppGUI:
    def __init__(self, master):
        self.master = master
        master.title("Aplikacja Szyfrująca")
        master.geometry("400x400")

        self.main_frame = tk.Frame(master)
        self.cipher_frame = tk.Frame(master)

        self.setup_main_frame()
        self.setup_cipher_frame()

        self.show_main_frame()

    def setup_main_frame(self):
        self.main_frame.pack(expand=True)

        label = tk.Label(self.main_frame, text="Szyfrowanie", font=("Arial", 16))
        label.pack(pady=20)

        button_frame = tk.Frame(self.main_frame)
        button_frame.pack()

        buttons = [
            ("Podstawieniowe", lambda: self.show_cipher_frame("Podstawieniowe")),
            ("Transpozycyjne", lambda: self.show_cipher_frame("Transpozycyjne")),
            ("Polialfabetyczne", lambda: self.show_cipher_frame("Polialfabetyczne"))
        ]

        for text, command in buttons:
            tk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5, pady=10)

    def setup_cipher_frame(self):
        back_button = tk.Button(self.cipher_frame, text="←", command=self.show_main_frame)
        back_button.pack(anchor="nw", padx=10, pady=10)

        self.cipher_type_label = tk.Label(self.cipher_frame, text="", font=("Arial", 14))
        self.cipher_type_label.pack(pady=10)

        input_frame = tk.Frame(self.cipher_frame)
        input_frame.pack(pady=10)

        tk.Label(input_frame, text="Tekst do zaszyfrowania/odszyfrowania:").pack()
        self.text_input = tk.Text(input_frame, height=5, width=40)
        self.text_input.pack()

        tk.Button(input_frame, text="Wybierz plik", command=self.load_file).pack(pady=5)

        button_frame = tk.Frame(self.cipher_frame)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Szyfrowanie", command=lambda: self.process_text("szyfrowanie")).pack(side=tk.LEFT,
                                                                                                           padx=5)
        tk.Button(button_frame, text="Odszyfrowywanie", command=lambda: self.process_text("odszyfrowywanie")).pack(
            side=tk.LEFT, padx=5)

        self.cipher_result_text = scrolledtext.ScrolledText(self.cipher_frame, height=5, width=40, wrap=tk.WORD)
        self.cipher_result_text.pack(pady=10)
        self.cipher_result_text.config(state=tk.DISABLED)

    def show_main_frame(self):
        self.cipher_frame.pack_forget()
        self.main_frame.pack(expand=True)

    def show_cipher_frame(self, cipher_type):
        self.main_frame.pack_forget()
        self.cipher_frame.pack(fill=tk.BOTH, expand=True)
        self.cipher_type_label.config(text=f"Szyfrowanie {cipher_type}")
        self.current_cipher_type = cipher_type
        self.cipher_result_text.config(state=tk.NORMAL)
        self.cipher_result_text.delete('1.0', tk.END)
        self.cipher_result_text.config(state=tk.DISABLED)

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Pliki tekstowe", "*.txt")])
        if file_path:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                self.text_input.delete('1.0', tk.END)
                self.text_input.insert(tk.END, content)

    def process_text(self, action):
        text = self.text_input.get('1.0', tk.END).strip()
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
            elif self.current_cipher_type == "Polialfabetyczne":
                if action == "szyfrowanie":
                    result = polialfabetyczne_szyfrowanie(text)
                else:
                    result = polialfabetyczne_deszyfrowanie(text)

            self.cipher_result_text.config(state=tk.NORMAL)
            self.cipher_result_text.delete('1.0', tk.END)
            self.cipher_result_text.insert(tk.END, f"Wynik {action}a: {result}")
            self.cipher_result_text.config(state=tk.DISABLED)
        else:
            self.cipher_result_text.config(state=tk.NORMAL)
            self.cipher_result_text.delete('1.0', tk.END)
            self.cipher_result_text.insert(tk.END, "Proszę wprowadzić tekst lub wybrać plik.")
            self.cipher_result_text.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = AppGUI(root)
    root.mainloop()