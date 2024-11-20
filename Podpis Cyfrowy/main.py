from PyQt5.QtWidgets import (QApplication, QMainWindow, QStackedWidget, QVBoxLayout,
                             QPushButton, QWidget, QLabel, QHBoxLayout, QFrame)
from PyQt5.QtCore import QPropertyAnimation, QEasingCurve, Qt
from PyQt5.QtGui import QFont, QPixmap
from GUI.generate_keys_gui import GenerateKeysWidget
from GUI.sign_page_gui import SignPageWidget
from GUI.verify_page_gui import VerifyPageWidget

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Aplikacja Podpisu Cyfrowego")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8f9fa;
            }
        """)

        # Główne widgety
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setSpacing(0)
        self.main_layout.setContentsMargins(0, 0, 0, 0)

        # Sidebar
        self.sidebar = QVBoxLayout()
        self.sidebar.setSpacing(1)
        self.sidebar.setContentsMargins(0, 0, 0, 0)

        self.sidebar_frame = QFrame()
        self.sidebar_frame.setStyleSheet("""
            QFrame {
                background-color: #1e1e2d;
                border: none;
            }
        """)
        self.sidebar_frame.setLayout(self.sidebar)
        self.sidebar_frame.setFixedWidth(200)

        # Logo/Tytuł w sidebarze
        self.logo_label = QLabel("Podpis Cyfrowy")
        self.logo_label.setStyleSheet("""
            QLabel {
                color: #ffffff;
                font-size: 16px;
                font-weight: bold;
                padding: 20px 15px;
                background-color: #151521;
            }
        """)
        self.sidebar.addWidget(self.logo_label)

        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setStyleSheet("""
            QFrame {
                border: none;
                background-color: #2d2d3f;
                height: 1px;
            }
        """)
        self.sidebar.addWidget(separator)

        # Container na przyciski menu
        self.menu_container = QWidget()
        self.menu_layout = QVBoxLayout(self.menu_container)
        self.menu_layout.setSpacing(2)
        self.menu_layout.setContentsMargins(8, 10, 8, 10)
        self.sidebar.addWidget(self.menu_container)

        self.main_layout.addWidget(self.sidebar_frame)

        # StackedWidget (przełączanie widoków)
        self.pages_container = QFrame()
        self.pages_container.setStyleSheet("""
            QFrame {
                background-color: #ffffff;
                border-top-left-radius: 15px;
                margin: 0px;
            }
        """)
        self.pages_layout = QVBoxLayout(self.pages_container)
        self.pages_layout.setContentsMargins(0, 0, 0, 0)

        self.pages = QStackedWidget()
        self.pages_layout.addWidget(self.pages)
        self.main_layout.addWidget(self.pages_container)

        # Strony
        self.home_page = QWidget()
        self.setup_home_page()
        self.generate_page = QWidget()
        self.setup_generate_page()
        self.sign_page = QWidget()
        self.setup_sign_page()
        self.verify_page = QWidget()
        self.setup_verify_page()

        self.pages.addWidget(self.home_page)
        self.pages.addWidget(self.generate_page)
        self.pages.addWidget(self.sign_page)
        self.pages.addWidget(self.verify_page)

        # Przyciski w menu
        self.current_button = None
        self.add_sidebar_button("🏠", "Strona Główna", self.home_page)
        self.add_sidebar_button("🔑", "Generowanie", self.generate_page)
        self.add_sidebar_button("📝", "Podpisywanie", self.sign_page)
        self.add_sidebar_button("✔️", "Weryfikacja", self.verify_page)

        # Dodajemy elastyczny spacer
        self.menu_layout.addStretch()

        # Stopka sidebara
        self.footer_label = QLabel("Marcin Gonciarz\nnr albumu: 31240")
        self.footer_label.setStyleSheet("""
            QLabel {
                color: #6d6d80;
                font-size: 12px;
                padding: 15px;
                background-color: #151521;
            }
        """)
        self.sidebar.addWidget(self.footer_label)

    def setup_home_page(self):
        """Konfiguracja strony głównej"""
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("Strona Główna")
        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #1e1e2d;
                margin-bottom: 20px;
            }
        """)
        layout.addWidget(title)

        subtitle = QLabel("Witaj w aplikacji do podpisu cyfrowego")
        subtitle.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #6d6d80;
            }
        """)
        layout.addWidget(subtitle)

        # Dodanie ikony na środku
        icon_label = QLabel()
        pixmap = QPixmap("ikona.webp")  # Upewnij się, że ścieżka do pliku jest poprawna

        icon_label.setPixmap(pixmap)  # Ustaw pixmapę
        icon_label.setScaledContents(True)  # Włącz skalowanie zawartości
        icon_label.setAlignment(Qt.AlignCenter)  # Wyśrodkowanie ikony
        layout.addWidget(icon_label)

        layout.addStretch()
        self.home_page.setLayout(layout)

        # Ustawienie minimalnych wymiarów QLabel, aby obrazek był responsywny
        icon_label.setMinimumSize(100, 100)  # Możesz dostosować minimalny rozmiar

    def setup_generate_page(self):
        """Konfiguracja zakładki: Generowanie Kluczy"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Użyj nowego widgetu GenerateKeysWidget
        generate_keys_widget = GenerateKeysWidget()
        layout.addWidget(generate_keys_widget)

        self.generate_page.setLayout(layout)

    def setup_sign_page(self):
        """Konfiguracja zakładki: Podpisywanie Dokumentów"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Użyj widgetu SignPageWidget
        sign_page_widget = SignPageWidget()
        layout.addWidget(sign_page_widget)

        self.sign_page.setLayout(layout)

    def setup_verify_page(self):
        """Konfiguracja zakładki: Weryfikacja Podpisów"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Użyj widgetu VerifyPageWidget
        verify_page_widget = VerifyPageWidget()
        layout.addWidget(verify_page_widget)

        self.verify_page.setLayout(layout)

    def add_sidebar_button(self, icon, text, target_page):
        """Dodaje przycisk do sidebar-a z animacją"""
        button = QPushButton(f" {icon}  {text}")
        button.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding: 12px 15px;
                font-size: 14px;
                color: #a2a3b7;
                border: none;
                border-radius: 5px;
                background-color: transparent;
            }
            QPushButton:hover {
                background-color: #2d2d3f;
                color: #ffffff;
            }
            QPushButton[active="true"] {
                background-color: #2d2d3f;
                color: #ffffff;
                border-left: 4px solid #3699ff;
            }
        """)

        def on_click():
            if self.current_button:
                self.current_button.setProperty("active", False)
                self.current_button.setStyle(self.current_button.style())

            button.setProperty("active", True)
            button.setStyle(button.style())
            self.current_button = button

            self.animate_page_transition(target_page)

        button.clicked.connect(on_click)
        self.menu_layout.addWidget(button)

    def animate_page_transition(self, target_page):
        """Animacja przejścia między stronami"""
        self.pages.setCurrentWidget(target_page)

        fade_anim = QPropertyAnimation(target_page, b"windowOpacity")
        fade_anim.setDuration(300)
        fade_anim.setStartValue(0.0)
        fade_anim.setEndValue(1.0)
        fade_anim.setEasingCurve(QEasingCurve.OutCubic)
        fade_anim.start()


if __name__ == "__main__":
    app = QApplication([])

    # Ustawienie globalnej czcionki
    font = QFont("Segoe UI", 10)
    app.setFont(font)

    window = MainWindow()
    window.show()
    app.exec_()