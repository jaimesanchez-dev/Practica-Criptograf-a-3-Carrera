from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from funciones_json import load_json, save_json, initialize_files
from crear_usuarios import save_clave_privada, save_clave_publica, cargar_clave_privada, cargar_clave_publica

from datetime import datetime

USERS_FILE = r"jsons\users.json"
MESSAGES_FILE = r"jsons\messages.json"
KEYS_FILE = r"jsons\keys.json"

class CifradoHibrido:
    """Clase que se encarga del cifrado híbrido de mensajes (asimétrico + simétrico)"""

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

        # Guardamos las claves en formato PEM
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


    def encriptado_hibrido(self, emisor, receptor, texto):
        """
        Función que encripta un mensaje usando cifrado híbrido:
        1. Genera una clave simétrica aleatoria
        2. Cifra el mensaje con la clave simétrica (Fernet)
        3. Cifra la clave simétrica con la clave pública del receptor (RSA)
        """
        # Cargamos los mensajes
        self.messages_db = load_json(self.messages_file)

        # PASO 1: Generar clave simétrica temporal para este mensaje
        clave_simetrica = Fernet.generate_key()
        fernet = Fernet(clave_simetrica)

        # PASO 2: Cifrar el mensaje con la clave simétrica
        texto_cifrado = fernet.encrypt(texto.encode())

        # PASO 3: Cifrar la clave simétrica con la clave pública del receptor
        public_key = cargar_clave_publica(receptor)
        clave_simetrica_cifrada = public_key.encrypt(
            clave_simetrica,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # PASO 4: Guardar el mensaje con ambos componentes
        mensaje = {
            "emisor": emisor,
            "receptor": receptor,
            "fecha_envio": datetime.now().isoformat(),
            "clave_cifrada": clave_simetrica_cifrada.hex(),  # Clave simétrica cifrada con RSA
            "texto_cifrado": texto_cifrado.decode()           # Mensaje cifrado con Fernet
        }

        self.messages_db["mensajes"].append(mensaje)
        save_json(self.messages_file, self.messages_db)

        print(f"Mensaje cifrado (híbrido) de {emisor} para {receptor}\n")
        return True
    

    def desencriptado_hibrido(self, usuario):
        """
        Desencripta los mensajes usando cifrado híbrido:
        1. Descifra la clave simétrica con la clave privada del usuario (RSA)
        2. Descifra el mensaje con la clave simétrica (Fernet)
        """
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
                # PASO 1: Descifrar la clave simétrica con la clave privada (RSA)
                clave_cifrada_bytes = bytes.fromhex(mensaje["clave_cifrada"])
                clave_simetrica = private_key.decrypt(
                    clave_cifrada_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # PASO 2: Descifrar el mensaje con la clave simétrica (Fernet)
                fernet = Fernet(clave_simetrica)
                texto_plano = fernet.decrypt(mensaje["texto_cifrado"].encode()).decode()

                print(f"De: {mensaje['emisor']} | Fecha: {mensaje['fecha_envio']}\n")
                print(f"   Mensaje: {texto_plano}\n")

            except Exception as e:
                print(f"No se pudo descifrar un mensaje: {e}")

        return True