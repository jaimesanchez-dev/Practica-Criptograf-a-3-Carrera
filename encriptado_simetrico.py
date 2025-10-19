from cryptography.fernet import Fernet
import re
from datetime import datetime
import os
from funciones_json import load_json, save_json, initialize_files

USERS_FILE = r"jsons\users.json"
MESSAGES_FILE = r"jsons\messages.json"
KEYS_FILE = r"jsons\keys.json"

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

    def generar_clave_simetrica(self, usuario):
        """Genera y guarda una clave Fernet para un usuario en keys.json"""
        # Cargamos los archivos json que vamos a usar
        self.users_db = load_json(self.users_file)
        self.keys_db = load_json(self.keys_file)

        # Si el usuario no existe, devolvemos False (no podemos generar clave)
        if usuario not in self.users_db:
            print(f"Usuario '{usuario}' no existe.")
            return False

        # En otro caso, la generamos y aplicamos .decode para poder almacenarla en el json
        # (Con el .decode la transformamos de bytes a string para poder guardarla en el json)
        key = Fernet.generate_key().decode()
        self.keys_db[usuario] = {
            "fernet_key": key,
            "fecha_creacion": datetime.now().isoformat()
        }

        # Guardamos los nuevos datos en nuestro fichero
        save_json(self.keys_file, self.keys_db)
        print(f"Clave Fernet generada y almacenada en '{self.keys_file}' para usuario '{usuario}'.\n")
        return True
    
    def encriptado_simetrico(self, emisor, receptor, texto):
        """Función que encripa un mensaje"""
        # Cargamos los ficheros que vamos a utilizar
        self.keys_db = load_json(self.keys_file)
        self.messages_db = load_json(self.messages_file)

        # Si el que envía el mensaje no tiene una clave de cifrado asignada, se le genera una
        if emisor not in self.keys_db:
            self.generar_clave(emisor)

        # Sacamos la clave del usuario y la transformamos de string a bytes
        key = self.keys_db[emisor]["fernet_key"].encode()
        # Creamos el cifrador fernet a través de la clave del usuario
        fernet = Fernet(key)
        # Ciframos el texto con .encrypt y usamos .encode en el mensaje para pasarlo a bytes
        texto_cifrado = fernet.encrypt(texto.encode())

        # Guardamos los datos del mensaje
        mensaje = {
            "emisor": emisor,
            "receptor": receptor,
            "fecha_envio": datetime.now().isoformat(),
            "texto_cifrado": texto_cifrado.decode()
        }

        # Guardamos el mensaje en la base de datos
        self.messages_db["mensajes"].append(mensaje)

        # Guardamos el json
        save_json(self.messages_file, self.messages_db)

        print(f"Mensaje cifrado y guardado correctamente.")
        return True
    
    def desencriptado_simetrico(self, usuario):
        """Función que desencripta un mensaje"""
        self.keys_db = load_json(self.keys_file)
        self.messages_db = load_json(self.messages_file)
        
        # Buscamos cuál de todos los mensajes tiene como receptor al usuario en cuestión
        inbox = [m for m in self.messages_db["mensajes"] if m["receptor"] == usuario]

        # Si no hay mensajes devolvemos False
        if not inbox:
            print("No hay mensajes para este usuario.\n")
            return False
        
        #Empezamos a sacar todos los mensajes que el usuario ha recibido
        print(f"--- Bandeja de entrada de {usuario} ---\n")
        for mensaje in inbox:
            # Pasamos la clave guardada en el json a bytes
            key = self.keys_db[mensaje["emisor"]]["fernet_key"].encode()
            # Creamos el cifrador fernet a partir de la clave
            fernet = Fernet(key)
            try:
                # Desencriptamos el mensaje pasándolos primero a bytes con .encode y el resultado final 
                # lo ponemos en forma de string con .decode
                texto = fernet.decrypt(mensaje["texto_cifrado"].encode()).decode()
                print(f"De: {mensaje['emisor']} | Fecha: {mensaje['fecha_envio']}\n")
                print(f"Mensaje descifrado: {texto}")
            except Exception as e:
                print(f"[ERROR] No se pudo descifrar el mensaje: {e}")
        