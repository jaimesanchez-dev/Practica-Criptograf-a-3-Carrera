from cryptography.fernet import Fernet
import re
from datetime import datetime
import os
from funciones_json import load_json, save_json, initialize_files

USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"
KEYS_FILE = "keys.json"

class CifradoSimetrico:
    """Gestiona el cifrado y descifrado de mensajes usando Fernet"""

    def __init__(self, users_file=USERS_FILE, messages_file=MESSAGES_FILE, keys_file=KEYS_FILE):
        """Inicializamos el sistema de cifrado"""
        self.users_file = users_file
        self.messages_file = messages_file
        self.keys_file = keys_file

        # Inicializamos los ficheros por si no existen
        initialize_files()

        self.users_db = load_json(self.users_file)
        self.messages_db = load_json(self.messages_file)
        self.keys_db = load_json(self.keys_file)

    def generar_clave(self, username):
        """Genera y guarda una clave Fernet para un usuario en keys.json"""
        # Cargamos los archivos json que vamos a usar
        self.users_db = load_json(self.users_file)
        self.keys_db = load_json(self.keys_file)

        # Si el usuario no existe, devolvemos False (no podemos generar clave)
        if username not in self.users_db:
            print(f"Usuario '{username}' no existe.")
            return False

        # En otro caso, la generamos y aplicamos .decode para poder almacenarla en el json
        # (Con el .decode la transformamos de bytes a string para poder guardarla en el json)
        key = Fernet.generate_key().decode()
        self.keys_db[username] = {
            "fernet_key": key,
            "created_at": datetime.now().isoformat()
        }

        # Guardamos los nuevos datos en nuestro fichero
        save_json(self.keys_file, self.keys_db)
        print(f"Clave Fernet generada y almacenada en '{self.keys_file}' para usuario '{username}'.\n")
        return True
    
    def encriptar_mensaje(self, sender, recipient, plaintext):
        """Función que encripa un mensaje"""
        # Cargamos los ficheros que vamos a utilizar
        self.keys_db = load_json(self.keys_file)
        self.messages_db = load_json(self.messages_file)

        if sender not in self.keys_db or recipient not in self.keys_db:
            print("Remitente o destinatario sin clave Fernet generada.")
            return False

        # Sacamos la clave del usuario y la transformamos de string a bytes
        key = self.keys_db[sender]["fernet_key"].encode()
        # Creamos el cifrador fernet a través de la clave del usuario
        fernet = Fernet(key)
        # Ciframos el texto con .encrypt y usamos .encode en el mensaje para pasarlo a bytes
        ciphertext = fernet.encrypt(plaintext.encode())

        # Guardamos los datos del mensaje
        msg = {
            "sender": sender,
            "recipient": recipient,
            "timestamp": datetime.now().isoformat(),
            "ciphertext": ciphertext.decode()
        }

        # Guardamos el mensaje en la base de datos
        self.messages_db["messages"].append(msg)

        # Guardamos el json
        save_json(self.messages_file, self.messages_db)

        print(f"Mensaje cifrado y guardado correctamente.")
        return True
    
    def desencriptar_mensaje(self, username):
        """Función que desencripta un mensaje"""
        self.keys_db = load_json(self.keys_file)
        self.messages_db = load_json(self.messages_file)

        # Si el usuario no tiene clave, devolvemos False
        if username not in self.keys_db:
            print(f"El usuario '{username}' no tiene clave Fernet.")
            return False
        
        # Buscamos cuál de todos los mensajes tiene como receptor al usuario en cuestión
        inbox = [m for m in self.messages_db["messages"] if m["recipient"] == username]

        # Si no hay mensajes devolvemos False
        if not inbox:
            print("No hay mensajes para este usuario.\n")
            return False
        
        #Empezamos a sacar todos los mensajes que el usuario ha recibido
        print(f"--- Bandeja de entrada de {username} ---\n")
        for mensaje in inbox:
            # Pasamos la clave guardada en el json a bytes
            key = self.keys_db[mensaje["sender"]]["fernet_key"].encode()
            # Creamos el cifrador fernet a partir de la clave
            fernet = Fernet(key)
            try:
                # Desencriptamos el mensaje pasándolos primero a bytes con .encode y el resultado final 
                # lo ponemos en forma de string con .decode
                plaintext = fernet.decrypt(mensaje["ciphertext"].encode()).decode()
                print(f"De: {mensaje['sender']} | Fecha: {mensaje['timestamp']}\n")
                print(f"Mensaje descifrado: {plaintext}")
            except Exception as e:
                print(f"[ERROR] No se pudo descifrar el mensaje: {e}")
        