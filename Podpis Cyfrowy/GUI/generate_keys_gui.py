from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel, QLineEdit,
                             QPushButton, QMessageBox, QFileDialog, QHBoxLayout)
from PyQt5.QtCore import QRegExp
from PyQt5.QtGui import QRegExpValidator
from Function.key_generator import KeyGenerator
from Function.certificate_generator import CertificateGenerator  # Zaktualizowana klasa generująca certyfikat


class GenerateKeysWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        # Rząd z tytułem i przyciskiem Wyczyść
        title_row = QHBoxLayout()

        # Tytuł
        title = QLabel("Generowanie Kluczy i Certyfikatu")
        title.setStyleSheet("""font-size: 24px; font-weight: bold; color: #1e1e2d; margin-bottom: 20px;""")

        # Przycisk Wyczyść
        clear_btn = QPushButton("✖")  # Użyj znaku X
        clear_btn.setFixedSize(30, 30)  # Mały kwadrat
        clear_btn.setStyleSheet(""" 
                          QPushButton { 
                              background-color: #ff6b6b; 
                              color: white; 
                              border: none; 
                              border-radius: 5px; 
                          }
                          QPushButton:hover { 
                              background-color: #ff4757; 
                          } 
                      """)
        clear_btn.clicked.connect(self.clear_all_fields)

        # Dodaj tytuł i przycisk do rzędu
        title_row.addWidget(title)
        title_row.addStretch()  # Rozciąga przestrzeń
        title_row.addWidget(clear_btn)

        # Dodaj rząd do głównego layoutu
        layout.addLayout(title_row)

        # Opis
        description = QLabel("Wygeneruj klucz prywatny, klucz publiczny oraz certyfikat X.509.")
        description.setStyleSheet("color: #6d6d80; margin-bottom: 10px;")
        layout.addWidget(description)

        # Wybór folderu do zapisania kluczy
        self.folder_input = QLineEdit(self)
        self.folder_input.setPlaceholderText("Wybierz folder do zapisania kluczy...")
        self.folder_input.setReadOnly(True)
        folder_btn = QPushButton("Wybierz folder")
        folder_btn.setStyleSheet("""
                                    QPushButton {
                                        background-color: #78B2D1;
                                        color: white;
                                        padding: 5px;
                                        border: none;
                                        border-radius: 5px;
                                        width: 180px;
                                        height: 15px;
                                    }
                                    QPushButton:hover {
                                        background-color: #192C2F;
                                    }
                                """)
        folder_btn.clicked.connect(self.select_folder)
        folder_layout = QHBoxLayout()
        folder_layout.addWidget(self.folder_input)
        folder_layout.addWidget(folder_btn)
        layout.addLayout(folder_layout)

        # Pola na dane osobowe
        self.full_name_input = QLineEdit(self)
        self.full_name_input.setPlaceholderText("Imię i nazwisko")
        layout.addWidget(self.full_name_input)

        # Numer PESEL/NIP (11 cyfr)
        self.pesel_nip_input = QLineEdit(self)
        self.pesel_nip_input.setPlaceholderText("Numer PESEL/NIP")
        self.pesel_nip_input.setMaxLength(11)  # Ograniczenie do 11 znaków
        pesel_validator = QRegExpValidator(QRegExp("^[0-9]{11}$"))  # Akceptowanie tylko cyfr
        self.pesel_nip_input.setValidator(pesel_validator)
        layout.addWidget(self.pesel_nip_input)

        self.address_input = QLineEdit(self)
        self.address_input.setPlaceholderText("Adres")
        layout.addWidget(self.address_input)

        self.representative_input = QLineEdit(self)
        self.representative_input.setPlaceholderText("Osoba reprezentująca (jeśli dotyczy)")
        layout.addWidget(self.representative_input)

        # Przycisk generowania kluczy i certyfikatu
        generate_btn = QPushButton("Wygeneruj Klucze i Certyfikat")
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #3699ff;
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2684ff;
            }
        """)
        generate_btn.clicked.connect(self.generate_keys_and_certificate)
        layout.addWidget(generate_btn)

        # Rozciągnięcie layoutu
        layout.addStretch()

        self.setLayout(layout)

    def select_folder(self):
        # Otwórz okno eksploratora, aby wybrać folder
        folder = QFileDialog.getExistingDirectory(self, "Wybierz folder do zapisania kluczy")
        if folder:
            self.folder_input.setText(folder)

    def generate_keys_and_certificate(self):
        folder = self.folder_input.text()
        full_name = self.full_name_input.text()
        pesel_nip = self.pesel_nip_input.text()
        address = self.address_input.text()
        representative = self.representative_input.text()

        if not folder or not full_name or not pesel_nip or not address:
            QMessageBox.warning(self, "Błąd", "Proszę uzupełnić wszystkie dane.")
            return

        try:
            # Generowanie kluczy
            key_generator = KeyGenerator(folder)
            private_key_path, public_key_path = key_generator.generate_key_pair()

            # Generowanie certyfikatu
            cert_generator = CertificateGenerator(
                private_key_path=private_key_path,
                cert_folder=folder,
                subject_name=full_name,
                pesel_nip=pesel_nip,
                address=address,
                representative=representative,
            )
            cert_path = cert_generator.generate_certificate()

            QMessageBox.information(self, "Sukces", f"Klucze i certyfikat zostały wygenerowane pomyślnie!\nCertyfikat: {cert_path}")

        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Nie udało się wygenerować kluczy i certyfikatu: {str(e)}")


    def clear_all_fields(self):
        # Wyczyść ścieżki plików
        self.folder_input.clear()
        self.full_name_input.clear()
        self.pesel_nip_input.clear()
        self.address_input.clear()
        self.representative_input.clear()
