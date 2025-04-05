import os
import hashlib
import base64
import sqlite3
import logging
from PyQt6 import QtWidgets, QtGui, QtCore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from reportlab.pdfgen import canvas
from datetime import datetime

# ----------------- Configuration -----------------
DB_FILE = "key_storage.db"
LOG_FILE = "encryption_tool.log"

# Logging setup
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")


# Key storage initialization
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, password TEXT, salt BLOB)''')
    conn.commit()
    conn.close()


# Generate a secure key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Generate a random salt
def generate_salt() -> bytes:
    return os.urandom(16)


# AES Encryption
def encrypt_file(file_path, password):
    salt = generate_salt()
    key = derive_key(password, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        plaintext = f.read()

    # Padding
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length] * padding_length)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file = file_path + ".enc"
    with open(encrypted_file, "wb") as f:
        f.write(salt + iv + ciphertext)

    logging.info(f"Encrypted {file_path} -> {encrypted_file}")
    return encrypted_file


# AES Decryption
def decrypt_file(encrypted_file, password):
    with open(encrypted_file, "rb") as f:
        data = f.read()

    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    decrypted_file = encrypted_file.replace(".enc", ".dec")
    with open(decrypted_file, "wb") as f:
        f.write(plaintext)

    logging.info(f"Decrypted {encrypted_file} -> {decrypted_file}")
    return decrypted_file


# Generate Report
def generate_report(encrypted_files):
    report_name = f"encryption_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
    c = canvas.Canvas(report_name)
    c.drawString(100, 750, "Encryption Report")
    y = 730

    for file in encrypted_files:
        c.drawString(100, y, f"Encrypted: {file}")
        y -= 20

    c.save()
    logging.info(f"Report generated: {report_name}")


# ----------------- GUI Application -----------------
class EncryptionApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("AES-256 File Encryption")
        self.setGeometry(100, 100, 500, 300)

        layout = QtWidgets.QVBoxLayout()

        # File Selection
        self.file_label = QtWidgets.QLabel("No file selected")
        self.file_button = QtWidgets.QPushButton("Select File")
        self.file_button.clicked.connect(self.select_file)

        # Password Input
        self.password_label = QtWidgets.QLabel("Enter Password:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        # Encrypt Button
        self.encrypt_button = QtWidgets.QPushButton("Encrypt")
        self.encrypt_button.clicked.connect(self.encrypt_action)

        # Decrypt Button
        self.decrypt_button = QtWidgets.QPushButton("Decrypt")
        self.decrypt_button.clicked.connect(self.decrypt_action)

        # Log Viewer
        self.log_viewer = QtWidgets.QTextEdit()
        self.log_viewer.setReadOnly(True)

        # Add Widgets to Layout
        layout.addWidget(self.file_label)
        layout.addWidget(self.file_button)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(self.log_viewer)

        self.setLayout(layout)

    def select_file(self):
        
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*)"
        )
        if file_path:
            self.file_label.setText(file_path)
            self.selected_file = file_path

    def encrypt_action(self):
        if hasattr(self, 'selected_file'):
            password = self.password_input.text()
            if password:
                encrypted_file = encrypt_file(self.selected_file, password)
                self.log_viewer.append(f"Encrypted: {encrypted_file}")
            else:
                self.log_viewer.append("Enter a password!")
        else:
            self.log_viewer.append("Select a file first!")

    def decrypt_action(self):
        if hasattr(self, 'selected_file'):
            password = self.password_input.text()
            if password:
                decrypted_file = decrypt_file(self.selected_file, password)
                self.log_viewer.append(f"Decrypted: {decrypted_file}")
            else:
                self.log_viewer.append("Enter a password!")
        else:
            self.log_viewer.append("Select a file first!")


# ----------------- Main Execution -----------------
if __name__ == "__main__":
    import sys
    init_db()

    app = QtWidgets.QApplication(sys.argv)
    window = EncryptionApp()
    window.show()
    sys.exit(app.exec())
