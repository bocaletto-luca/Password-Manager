# Software Name: Password Manager
# Author: Bocaletto Luca
# Site Web: https://www.elektronoide.it

import sys
import sqlite3
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from cryptography.fernet import Fernet, InvalidToken, InvalidSignature

# Definizione della classe principale PasswordManager
class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 400, 200)
        
        # Connessione al database SQLite per le password
        try:
            self.conn = sqlite3.connect("passwords.db")
            self.create_table()
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Errore", "Impossibile connettersi al database: " + str(e))
            sys.exit(1)
        
        # Carica o genera la chiave di crittografia
        self.key = self.load_or_generate_key()
        
        # Inizializza l'interfaccia utente
        self.init_ui()
    
    # Crea la tabella per le password nel database se non esiste già
    def create_table(self):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                              (id INTEGER PRIMARY KEY,
                               service TEXT NOT NULL,
                               username TEXT NOT NULL,
                               password TEXT NOT NULL)''')
            self.conn.commit()
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Errore", "Impossibile creare la tabella: " + str(e))
            sys.exit(1)
    
    # Inizializza l'interfaccia utente Qt
    def init_ui(self):
        layout = QVBoxLayout()
        
        self.service_label = QLabel("Servizio:")
        self.service_input = QLineEdit()
        
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        
        self.save_button = QPushButton("Salva Password")
        self.save_button.clicked.connect(self.save_password)
        
        self.retrieve_button = QPushButton("Recupera Password")
        self.retrieve_button.clicked.connect(self.retrieve_password)
        
        layout.addWidget(self.service_label)
        layout.addWidget(self.service_input)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.save_button)
        layout.addWidget(self.retrieve_button)
        
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
    
    # Carica o genera la chiave di crittografia e la salva in un file
    def load_or_generate_key(self):
        key_file_path = "key.key"
        if os.path.exists(key_file_path):
            with open(key_file_path, "rb") as key_file:
                key = key_file.read()
        else:
            key = Fernet.generate_key()
            with open(key_file_path, "wb") as key_file:
                key_file.write(key)
        return key
    
    # Crittografa una password usando la chiave
    def encrypt_password(self, password, key):
        fernet = Fernet(key)
        return fernet.encrypt(password.encode())
    
    # Decrittografa una password usando la chiave
    def decrypt_password(self, encrypted_password, key):
        try:
            fernet = Fernet(key)
            return fernet.decrypt(encrypted_password).decode()
        except (InvalidToken, InvalidSignature) as e:
            print(f"Errore durante la decrittazione: {e}")
            return "Errore nella decrittazione"
    
    # Salva una nuova password nel database
    def save_password(self):
        service = self.service_input.text()
        username = self.username_input.text()
        password = self.password_input.text()
        
        if service and username and password:
            encrypted_password = self.encrypt_password(password, self.key)
            
            try:
                cursor = self.conn.cursor()
                cursor.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)", (service, username, encrypted_password))
                self.conn.commit()
                QMessageBox.information(self, "Successo", "Password salvata con successo!")
                self.service_input.clear()
                self.username_input.clear()
                self.password_input.clear()
            except sqlite3.Error as e:
                QMessageBox.critical(self, "Errore", "Errore durante il salvataggio della password: " + str(e))
        else:
            QMessageBox.warning(self, "Errore", "Tutti i campi sono obbligatori.")
    
    # Recupera e decrittografa una password dal database
    def retrieve_password(self):
        service = self.service_input.text()
        username = self.username_input.text()
        
        if service and username:
            try:
                cursor = self.conn.cursor()
                cursor.execute("SELECT password FROM passwords WHERE service=? AND username=?", (service, username))
                row = cursor.fetchone()
                if row:
                    encrypted_password = row[0]
                    decrypted_password = self.decrypt_password(encrypted_password, self.key)
                    self.password_input.setEchoMode(QLineEdit.Normal)  # Imposta il testo della password visibile
                    self.password_input.setText(decrypted_password)
                else:
                    self.password_input.clear()
                    QMessageBox.warning(self, "Errore", "Password non trovata.")
            except sqlite3.Error as e:
                QMessageBox.critical(self, "Errore", "Errore durante il recupero della password: " + str(e))
        else:
            QMessageBox.warning(self, "Errore", "Inserire il servizio e l'username.")

# Funzione principale per l'esecuzione del programma
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec_())
