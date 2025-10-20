from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from funciones_json import load_json, save_json, initialize_files
from crear_usuarios import save_clave_privada, save_clave_publica, cargar_clave_privada, cargar_clave_publica

import re
from datetime import datetime
import os

USERS_FILE = r"jsons\users.json"
MESSAGES_FILE = r"jsons\messages.json"
KEYS_FILE = r"jsons\keys.json"

class CifradoAsimetrico:
    """Clase que se encarga del cifrado asimétrico de mensajes"""

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

        # Guardamos las claves privada en la carpeta del usuario
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        save_clave_privada(usuario, private_pem)
        save_clave_publica(usuario, public_pem)


    def encriptado_asimetrico(self, emisor, receptor, texto):
        """Función que encripta un mensaje"""
        # Cargamos los mensajes y la clave pública del receptor
        self.messages_db = load_json(self.messages_file)

        public_key = cargar_clave_publica(receptor)

        # Ciframos el mensaje
        texto_cifrado = public_key.encrypt(
            texto.encode(),     # Pasamos el mensaje a bytes
            padding.OAEP(       # Rellenamos el mensaje para hacerlo más seguro
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Guardamos el mensaje
        mensaje = {
            "emisor": emisor,
            "receptor": receptor,
            "fecha_envio": datetime.now().isoformat(),
            "texto_cifrado": texto_cifrado.hex()    # Pasamos el texto a hexadecimal para poder guardarlo
        }

        self.messages_db["mensajes"].append(mensaje)
        save_json(self.messages_file, self.messages_db)

        print(f"Mensaje cifrado de {emisor} para {receptor}\n")
        return True
    

    def desencriptado_asimetrico(self, usuario):
        """Desencripta los mensajes que le enviaron al usuario"""

        self.messages_db = load_json(self.messages_file)

        # Buscar los mensajes que le enviaron al usuario
        inbox = [m for m in self.messages_db["mensajes"] if m["receptor"] == usuario]

        if not inbox:
            print(f"No hay mensajes para {usuario}.\n")
            return False

        # Cargar la clave privada del usuario
        private_key = cargar_clave_privada(usuario)

        print(f"--- Bandeja de entrada de {usuario} ---\n")
        for mensaje in inbox:
            try:
                # Convertir el texto cifrado de hex a bytes
                texto_bytes = bytes.fromhex(mensaje["texto_cifrado"])

                # Descifrar el mensaje
                texto_plano = private_key.decrypt(
                    texto_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                print(f"De: {mensaje['emisor']} | Fecha: {mensaje['fecha_envio']}\n")
                print(f"   Mensaje: {texto_plano.decode()}\n")

            except Exception as e:
                print(f"No se pudo descifrar un mensaje: {e}")

        return True
