from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QHBoxLayout, QPushButton, QFileDialog, QScrollArea
from cryptography.hazmat.primitives import serialization
from Function.signature_verifier import verify_signature
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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

    def verify_page(self):
        sig_file = self.file_sig_path_input.text()
        cert_file = self.file_cert_path_input.text()
        document_file = self.file_doc_path_input.text()

        if not (sig_file and cert_file and document_file):
            self.status_label.setText("Musisz wybrać wszystkie wymagane pliki.")
            self.status_label.setStyleSheet("color: red;")
            return

        try:
            # UWAGA: zmień na bardziej jednoznaczne sprawdzenie
            result = verify_signature(sig_file, cert_file, document_file)

            # Sprawdź dokładnie typ wyniku
            if result == "Podpis jest ważny!":
                self.status_label.setAlignment(Qt.AlignCenter)
                self.status_label.setText("Weryfikacja podpisu zakończona sukcesem!")
                self.status_label.setStyleSheet("""
                    color: green;
                    font-size: 16px;
                    font-weight: bold;
                    background-color: #e6ffe6;
                    padding: 5px;
                    border-radius: 5px;
                """)
                # Wyświetlenie danych certyfikatu
                cert_info = self.get_certificate_info(cert_file)
                self.update_cert_info(cert_info)
            else:
                self.status_label.setAlignment(Qt.AlignCenter)
                self.status_label.setText("Weryfikacja podpisu nie powiodła się.")
                self.status_label.setStyleSheet("""
                    color: red;
                    font-size: 16px;
                    font-weight: bold;
                    background-color: #ffe6e6;
                    padding: 5px;
                    border-radius: 5px;
                """)



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

    def update_cert_info(self, cert_info):
        # Czyści poprzednie informacje o certyfikacie
        for i in reversed(range(self.cert_info_layout.count())):
            widget = self.cert_info_layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()

        # Dodaje nowe informacje o certyfikacie
        cert_info_label = QLabel(cert_info)
        cert_info_label.setWordWrap(True)  # Umożliwia zawijanie tekstu
        cert_info_label.setAlignment(Qt.AlignCenter)  # Wyśrodkowanie
        cert_info_label.setStyleSheet("""
            font-size: 14px;  # Zwiększenie rozmiaru czcionki
            font-weight: bold;  # Pogrubienie tekstu
            background-color: #f0f0f0;  # Jasne tło
            padding: 10px;  # Dodanie wypełnienia
        """)
        self.cert_info_layout.addWidget(cert_info_label)
    def get_certificate_info(self, cert_file):
        with open(cert_file, 'rb') as f:
            cert_data = f.read()

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Słownik tłumaczeń nazw atrybutów
        attr_translations = {
            'commonName': 'Nazwa',
            'countryName': 'Kraj',
            'localityName': 'Miejscowość',
            'organizationalUnitName': 'Osoba reprezentująca',
            'streetAddress': 'Adres',
            'serialNumber': 'Numer PESEL'
        }

        # Zbieranie danych z certyfikatu
        cert_info = []

        # Dodawanie informacji o wystawcy w pionie
        cert_info.append("Podpisany przez:")
        for attribute in cert.issuer:
            # Próba przetłumaczenia nazwy atrybutu
            attr_name = attribute.oid._name
            translated_name = attr_translations.get(attr_name, attr_name)
            cert_info.append(f"{translated_name}: {attribute.value}")

        # Dodawanie pozostałych informacji
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

        # Łączenie wszystkich informacji w jeden string
        return "\n".join(cert_info)

    def clear_all_fields(self):
        # Wyczyść ścieżki plików
        self.file_sig_path_input.clear()
        self.file_cert_path_input.clear()
        self.file_doc_path_input.clear()
        # Wyczyść etykietę statusu
        self.status_label.clear()
        self.status_label.setStyleSheet("")

        # Wyczyść informacje o certyfikacie
        for i in reversed(range(self.cert_info_layout.count())):
            widget = self.cert_info_layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()


