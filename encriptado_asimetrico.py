from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import re
from datetime import datetime
import os
from funciones_json import load_json, save_json, initialize_files

USERS_FILE = r"jsons\users.json"
MESSAGES_FILE = r"jsons\messages.json"
KEYS_FILE = r"jsons\keys.json"

class CifradoAsimetrico:
    """aaaaaaaaaaaaaaaaa"""

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

    def generar_claves(self, usuario):
        """Función que genera la clave pública y privada de un usuario"""
        # Cargamos el json de claves
        self.keys_db = load_json(self.keys_file)

        # Creamos la clave privada
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # valor estándar
            key_size=2048           # longitud típica
        )
        
        # Creamos la clave pública a partir de la privada
        public_key = private_key.public_key()

        # Guardamos la clave privada en la carpeta del usuario
        


    def encriptado_asimetrico(self, emisor, receptor, texto):

        return False