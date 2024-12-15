from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QHBoxLayout, QPushButton, QFileDialog, QScrollArea
from cryptography.hazmat.primitives import serialization
from Function.signature_verifier import verify_signature
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import hmac
import hashlib

class VerifyPageWidget(QWidget):
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
        title = QLabel("Weryfikacja Podpisów")
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
        description = QLabel("Zweryfikuj podpis cyfrowy za pomocą klucza publicznego.")
        description.setStyleSheet("color: #6d6d80; margin-bottom: 10px;")
        layout.addWidget(description)

        self.file_sig_path_input = QLineEdit(self)
        self.file_sig_path_input.setPlaceholderText("Wybierz plik podpisany...")
        self.file_sig_path_input.setReadOnly(True)
        file_sig_btn = QPushButton("Wybierz plik podpisu")
        file_sig_btn.setStyleSheet(self.get_button_style())
        file_sig_btn.clicked.connect(self.select_sig_file)
        file_sig_layout = QHBoxLayout()
        file_sig_layout.addWidget(self.file_sig_path_input)
        file_sig_layout.addWidget(file_sig_btn)
        layout.addLayout(file_sig_layout)

        self.file_cert_path_input = QLineEdit(self)
        self.file_cert_path_input.setPlaceholderText("Wybierz certyfikat...")
        self.file_cert_path_input.setReadOnly(True)
        file_cert_btn = QPushButton("Wybierz certyfikat")
        file_cert_btn.setStyleSheet(self.get_button_style())
        file_cert_btn.clicked.connect(self.select_cert)
        file_cert_layout = QHBoxLayout()
        file_cert_layout.addWidget(self.file_cert_path_input)
        file_cert_layout.addWidget(file_cert_btn)
        layout.addLayout(file_cert_layout)

        # Dodaj input dla łańcucha certyfikatów
        self.file_cert_chain_path_input = QLineEdit(self)
        self.file_cert_chain_path_input.setPlaceholderText("Wybierz plik łańcucha certyfikatów...")
        self.file_cert_chain_path_input.setReadOnly(True)
        file_cert_chain_btn = QPushButton("Wybierz łańcuch certyfikatów")
        file_cert_chain_btn.setStyleSheet(self.get_button_style())
        file_cert_chain_btn.clicked.connect(self.select_cert_chain)
        file_cert_chain_layout = QHBoxLayout()
        file_cert_chain_layout.addWidget(self.file_cert_chain_path_input)
        file_cert_chain_layout.addWidget(file_cert_chain_btn)
        layout.addLayout(file_cert_chain_layout)

        self.file_doc_path_input = QLineEdit(self)
        self.file_doc_path_input.setPlaceholderText("Wybierz plik...")
        self.file_doc_path_input.setReadOnly(True)
        file_doc_btn = QPushButton("Wybierz plik")
        file_doc_btn.setStyleSheet(self.get_button_style())
        file_doc_btn.clicked.connect(self.select_document)
        file_doc_layout = QHBoxLayout()
        file_doc_layout.addWidget(self.file_doc_path_input)
        file_doc_layout.addWidget(file_doc_btn)
        layout.addLayout(file_doc_layout)

        self.file_hmac_path_input = QLineEdit(self)
        self.file_hmac_path_input.setPlaceholderText("Wybierz klucz HMac ...")
        self.file_hmac_path_input.setReadOnly(True)
        file_hmac_btn = QPushButton("Wybierz klucz HMac")
        file_hmac_btn.setStyleSheet(self.get_button_style())
        file_hmac_btn.clicked.connect(self.select_hmac)
        file_hmac_layout = QHBoxLayout()
        file_hmac_layout.addWidget(self.file_hmac_path_input)
        file_hmac_layout.addWidget(file_hmac_btn)
        layout.addLayout(file_hmac_layout)

        # Przycisk weryfikacji
        generate_btn = QPushButton("Zweryfikuj Podpis")
        generate_btn.setStyleSheet(""" QPushButton {
                                        background-color: #3699ff;
                                        color: white;
                                        padding: 10px;
                                        border: none;
                                        border-radius: 5px;
                                    }
                                    QPushButton:hover {
                                        background-color: #2684ff;
                                    }""")
        generate_btn.clicked.connect(self.verify_page)
        layout.addWidget(generate_btn)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("font-size: 14px; margin-top: 10px;")
        layout.addWidget(self.status_label)

        # Obszar przewijania dla cert_info
        self.cert_info_scroll_area = QScrollArea()
        self.cert_info_scroll_area.setWidgetResizable(True)
        self.cert_info_content = QWidget()
        self.cert_info_layout = QVBoxLayout(self.cert_info_content)
        self.cert_info_scroll_area.setWidget(self.cert_info_content)
        layout.addWidget(self.cert_info_scroll_area)

        # Ustawienie głównego layoutu
        self.setLayout(layout)

    def select_cert_chain(self):
        file, _ = QFileDialog.getOpenFileName(self, "Wybierz plik łańcucha certyfikatów", "",
                                              "Pliki certyfikatów (*.pem *.crt)")
        if file:
            self.file_cert_chain_path_input.setText(file)

    def get_certificate_chain(self, cert_chain_file):
        # Wczytaj certyfikaty z pliku łańcucha
        with open(cert_chain_file, 'rb') as f:
            cert_chain_data = f.read()

        # Rozdziel certyfikaty
        cert_texts = cert_chain_data.split(b'-----END CERTIFICATE-----')

        cert_chain = []
        for cert_text in cert_texts:
            if b'BEGIN CERTIFICATE' in cert_text:
                full_cert_text = cert_text + b'-----END CERTIFICATE-----'
                try:
                    cert = x509.load_pem_x509_certificate(full_cert_text, default_backend())
                    cert_chain.append(cert)
                except Exception as e:
                    print(f"Błąd wczytywania certyfikatu: {e}")

        if len(cert_chain) < 3:
            raise ValueError("Plik łańcucha certyfikatów musi zawierać co najmniej 3 certyfikaty")

        return cert_chain

    def get_button_style(self):
        return """ 
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
        """

    def select_sig_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Wybierz plik podpisu", "", "Pliki podpisów (*.sig)")
        if file:
            self.file_sig_path_input.setText(file)

    def select_cert(self):
        file, _ = QFileDialog.getOpenFileName(self, "Wybierz certyfikat", "", "Pliki certyfikatów (*.crt *.pem)")
        if file:
            self.file_cert_path_input.setText(file)

    def select_document(self):
        file, _ = QFileDialog.getOpenFileName(self, "Wybierz dokument", "", "Pliki dokumentów (*)")
        if file:
            self.file_doc_path_input.setText(file)

    def select_hmac(self):
        file, _ = QFileDialog.getOpenFileName(self, "Wybierz klucz HMac", "", "Pliki dokumentów (*)")
        if file:
            self.file_hmac_path_input.setText(file)

    def verify_page(self):
        sig_file = self.file_sig_path_input.text()
        cert_file = self.file_cert_path_input.text()
        document_file = self.file_doc_path_input.text()
        cert_chain_file = self.file_cert_chain_path_input.text()
        hmac_key_file = self.file_hmac_path_input.text()

        # Wyczyść informacje o certyfikacie
        for i in reversed(range(self.cert_info_layout.count())):
            widget = self.cert_info_layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()

        if not document_file or not sig_file:
            self.status_label.setText("Musisz wybrać dokument i podpis.")
            self.status_label.setStyleSheet("color: red;")
            return

        try:
            if cert_file and cert_chain_file:
                # --- Weryfikacja RSA ---
                # Załaduj certyfikat użytkownika
                user_cert = x509.load_pem_x509_certificate(open(cert_file, 'rb').read(), default_backend())
                public_key = user_cert.public_key()

                # Załaduj podpis
                with open(sig_file, 'rb') as sig:
                    signature = sig.read()

                # Załaduj dokument
                with open(document_file, 'rb') as doc:
                    document_data = doc.read()

                # Oblicz hash dokumentu
                digest = hashes.Hash(hashes.SHA256())
                digest.update(document_data)
                document_hash = digest.finalize()

                # Weryfikuj podpis
                public_key.verify(
                    signature,
                    document_hash,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )

                # Weryfikacja łańcucha certyfikatów
                cert_chain = self.get_certificate_chain(cert_chain_file)
                if not self.verify_certificate_chain(cert_chain):
                    self.status_label.setAlignment(Qt.AlignCenter)
                    self.status_label.setText("Łańcuch certyfikatów jest nieprawidłowy.")
                    self.status_label.setStyleSheet("""
                        color: red;
                        font-size: 16px;
                        font-weight: bold;
                        background-color: #ffe6e6;
                        padding: 5px;
                        border-radius: 5px;
                    """)
                    return

                first_cert = cert_chain[0]
                if user_cert.public_key() != first_cert.public_key():
                    self.status_label.setAlignment(Qt.AlignCenter)
                    self.status_label.setText(
                        "Certyfikat użytkownika nie jest zgodny z pierwszym certyfikatem w łańcuchu.")
                    self.status_label.setStyleSheet("""
                        color: red;
                        font-size: 16px;
                        font-weight: bold;
                        background-color: #ffe6e6;
                        padding: 5px;
                        border-radius: 5px;
                    """)
                    return

                self.status_label.setAlignment(Qt.AlignCenter)
                self.status_label.setText("Weryfikacja podpisu RSA zakończona sukcesem!")
                self.status_label.setStyleSheet("""
                    color: green;
                    font-size: 16px;
                    font-weight: bold;
                    background-color: #e6ffe6;
                    padding: 5px;
                    border-radius: 5px;
                """)
                # Wyświetlenie danych certyfikatu
                self.update_cert_chain_info(cert_chain)
            elif hmac_key_file:
                # --- Weryfikacja HMAC ---
                with open(hmac_key_file, 'r') as key_file:
                    hmac_key = key_file.read().strip()

                # Załaduj dokument
                with open(document_file, 'rb') as doc:
                    document_data = doc.read()

                # Załaduj podpis
                with open(sig_file, 'r') as sig:
                    signature = sig.read().strip()

                # Oblicz HMAC
                computed_hmac = hmac.new(hmac_key.encode(), document_data, hashlib.sha256).hexdigest()

                if computed_hmac != signature:
                    self.status_label.setAlignment(Qt.AlignCenter)
                    self.status_label.setText("Weryfikacja podpisu HMAC nie powiodła się.")
                    self.status_label.setStyleSheet("""
                        color: red;
                        font-size: 16px;
                        font-weight: bold;
                        background-color: #ffe6e6;
                        padding: 5px;
                        border-radius: 5px;
                    """)
                    return

                self.status_label.setAlignment(Qt.AlignCenter)
                self.status_label.setText("Weryfikacja podpisu HMAC zakończona sukcesem!")
                self.status_label.setStyleSheet("""
                    color: green;
                    font-size: 16px;
                    font-weight: bold;
                    background-color: #e6ffe6;
                    padding: 5px;
                    border-radius: 5px;
                """)

            else:
                self.status_label.setText("Nie podano wymaganych plików do weryfikacji.")
                self.status_label.setStyleSheet("color: red;")

        except Exception as e:
            self.status_label.setAlignment(Qt.AlignCenter)
            self.status_label.setText(f"Nie udało się zweryfikować podpisu: {str(e)}")
            self.status_label.setStyleSheet("""
                color: red;
                font-size: 16px;
                font-weight: bold;
                background-color: #ffe6e6;
                padding: 5px;
                border-radius: 5px;
            """)

    def verify_certificate_chain(self, cert_chain):
        for i in range(len(cert_chain) - 1):
            cert = cert_chain[i]
            issuer_cert = cert_chain[i + 1]

            # Sprawdzenie, czy certyfikat jest podpisany przez swojego wystawcę
            try:
                issuer_public_key = issuer_cert.public_key()
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            except Exception as e:
                print(f"Weryfikacja certyfikatu {i} nie powiodła się: {str(e)}")
                # Wyczyść informacje o certyfikacie
                for i in reversed(range(self.cert_info_layout.count())):
                    widget = self.cert_info_layout.itemAt(i).widget()
                    if widget is not None:
                        widget.deleteLater()
                return False
        return True

    def get_certificate_info_from_cert(self, cert):
        # Słownik tłumaczeń nazw atrybutów
        attr_translations = {
            'commonName': 'Nazwa',
            'countryName': 'Kraj',
            'localityName': 'Miejscowość',
            'organizationalUnitName': 'Osoba reprezentująca',
            'streetAddress': 'Adres',
            'serialNumber': 'Numer Pesel/NIP',  # Użyj odpowiedniego opisu
        }

        # Zbieranie danych z certyfikatu
        cert_info = []

        cert_info.append("------ Certyfikat ------")

        # Informacje o podmiocie
        cert_info.append("Dane podmiotu:")
        for attribute in cert.subject:
            attr_name = attribute.oid._name
            translated_name = attr_translations.get(attr_name, attr_name)
            cert_info.append(f"{translated_name}: {attribute.value}")

        cert_info.append("")

        # Informacje o emitencie
        cert_info.append("Dane emitenta:")
        for attribute in cert.issuer:
            attr_name = attribute.oid._name
            translated_name = attr_translations.get(attr_name, attr_name)
            cert_info.append(f"{translated_name}: {attribute.value}")

        cert_info.append(f"Ważny od: {cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S')}")
        cert_info.append(f"Ważny do: {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S')}")
        cert_info.append(f"Numer seryjny: {cert.serial_number}")

        public_key = cert.public_key()
        public_key_info = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        cert_info.append("Klucz publiczny:")
        cert_info.append(public_key_info)

        return "\n".join(cert_info)

    def update_cert_chain_info(self, cert_chain):
        # Czyści poprzednie informacje o certyfikacie
        for i in reversed(range(self.cert_info_layout.count())):
            widget = self.cert_info_layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()

        # Dodaje nowe informacje o każdym certyfikacie w łańcuchu
        for cert in cert_chain:
            cert_info = self.get_certificate_info_from_cert(cert)
            cert_info_label = QLabel(cert_info)
            cert_info_label.setWordWrap(True)
            cert_info_label.setAlignment(Qt.AlignCenter)  # Wyśrodkowanie tekstu
            cert_info_label.setStyleSheet("""
                background-color: #f0f0f0;
                border-radius: 5px;
                padding: 10px;
                margin: 5px 0;
            """)
            self.cert_info_layout.addWidget(cert_info_label)
    def clear_all_fields(self):
        # Wyczyść ścieżki plików
        self.file_sig_path_input.clear()
        self.file_cert_path_input.clear()
        self.file_doc_path_input.clear()
        self.file_cert_chain_path_input.clear()
        # Wyczyść etykietę statusu
        self.status_label.clear()
        self.status_label.setStyleSheet("")

        # Wyczyść informacje o certyfikacie
        for i in reversed(range(self.cert_info_layout.count())):
            widget = self.cert_info_layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()
