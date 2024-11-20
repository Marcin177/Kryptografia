from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QHBoxLayout

from Function.sign_executor import load_certificate_and_private_key  # Importujemy funkcje z osobnego pliku
from PyQt5.QtWidgets import QFileDialog, QMessageBox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class SignPageWidget(QWidget):
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
        title = QLabel("Podpisywanie Dokumentów")
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
        description = QLabel("Podpisz dokument swoim kluczem prywatnym.")
        description.setStyleSheet("color: #6d6d80; margin-bottom: 10px;")
        layout.addWidget(description)

        # Wybór pliku do podpisania
        self.file_path_input = QLineEdit(self)
        self.file_path_input.setPlaceholderText("Wybierz plik do podpisania...")
        self.file_path_input.setReadOnly(True)
        file_btn = QPushButton("Wybierz plik do podpisania")
        file_btn.setStyleSheet(""" 
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
        file_btn.clicked.connect(self.select_file_to_sign)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_path_input)
        file_layout.addWidget(file_btn)
        layout.addLayout(file_layout)

        # Wybór certyfikatu (PEM)
        self.key_path_input = QLineEdit(self)
        self.key_path_input.setPlaceholderText("Wybierz klucz prywatny (PEM)...")
        self.key_path_input.setReadOnly(True)
        key_btn = QPushButton("Wybierz klucz prywatny")
        key_btn.setStyleSheet(""" 
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
        key_btn.clicked.connect(self.select_key)
        key_layout = QHBoxLayout()
        key_layout.addWidget(self.key_path_input)
        key_layout.addWidget(key_btn)
        layout.addLayout(key_layout)

        # Przycisk podpisywania
        self.generate_btn = QPushButton("Podpisz Dokument")
        self.generate_btn.setStyleSheet(""" 
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
        self.generate_btn.clicked.connect(self.sign_document)
        layout.addWidget(self.generate_btn)

        # Rozciągnięcie layoutu
        layout.addStretch()

        self.setLayout(layout)

    def select_file_to_sign(self):
        """Pozwól użytkownikowi wybrać plik do podpisania."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Wybierz plik do podpisania", "", "Documents (*.pdf *.txt);;All Files (*)")
        if file_path:
            self.file_path_input.setText(file_path)

    def select_key(self):
        """Pozwól użytkownikowi wybrać klucz prywatny."""
        pem_file, _ = QFileDialog.getOpenFileName(self, "Wybierz klucz prywatny", "",
                                                  "Private Key Files (*.pem);;All Files (*)")
        if pem_file:
            self.key_path_input.setText(pem_file)

    def sign_document(self):
        document_path = self.file_path_input.text()
        pem_file_path = self.key_path_input.text()

        if not document_path or not pem_file_path:
            QMessageBox.critical(self, "Błąd", "Musisz wybrać plik do podpisania oraz certyfikat.")
            return

        try:
            # Załaduj klucz prywatny
            private_key, _ = load_certificate_and_private_key(pem_file_path)

            # Podpisz dokument
            with open(document_path, 'rb') as file:
                document_data = file.read()

            # Oblicz hash dokumentu
            digest = hashes.Hash(hashes.SHA256())
            digest.update(document_data)
            document_hash = digest.finalize()

            # Podpisz hash zamiast pełnych danych
            signature = private_key.sign(
                document_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            # Otwórz okno wyboru lokalizacji zapisu
            signature_path, _ = QFileDialog.getSaveFileName(self, "Zapisz podpisany dokument", "",
                                                            "Signature Files (*.sig);;All Files (*)")

            if signature_path:
                # Zapisz podpis do wybranej lokalizacji
                with open(signature_path, 'wb') as sig_file:
                    sig_file.write(signature)

                # Powiadom użytkownika o sukcesie
                QMessageBox.information(self, "Sukces",
                                        f"Dokument został podpisany. Podpis zapisano w: {signature_path}")
            else:
                # Jeśli użytkownik nie wybrał lokalizacji
                QMessageBox.warning(self, "Brak lokalizacji", "Nie wybrano lokalizacji do zapisania podpisu.")

        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Nie udało się podpisać dokumentu: {str(e)}")

    def clear_all_fields(self):
        # Wyczyść ścieżki plików
        self.file_path_input.clear()
        self.key_path_input.clear()
