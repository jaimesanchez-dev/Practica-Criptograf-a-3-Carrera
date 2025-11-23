from cryptography import x509
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from funciones_json import save_json, load_json, initialize_files
import os

CERTS_FILE = r"jsons\certificates.json"

class AutoridadCertificacion:
    """Clase para gestionar la Autoridad de Certificación"""
    
    def __init__(self, nombre, es_raiz=False, ca_superior=None):
        """ Inicializa una Autoridad """
        self.nombre = nombre
        self.es_raiz = es_raiz  #Es true si es la autoridad madre
        self.ca_superior = ca_superior #Si no es la autoridad madre, esta es su superior
        self.clave_privada = None
        self.clave_publica = None
        self.certificado = None
        self.certs_file = CERTS_FILE
        
        # Inicializar archivos ----------------------Creo qeu habrá que quitarlo
        initialize_files() 
        
    def generar_claves(self):
        """Genera el par de claves RSA para la CA"""
        
        self.clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.clave_publica = self.clave_privada.public_key()


    def _guardar_certificado(self):
        """Guarda el certificado de la CA en formato PEM"""
        cert_pem = self.certificado.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()
        
        path = f"jsons\\certificados\\{self.nombre}_cert.pem"
        with open(path, "w", encoding="utf-8") as f:
            f.write(cert_pem)
        
        print(f"[PKI] Certificado guardado en '{path}'")
        
        # También guardar en JSON para referencia
        certs_db = load_json(self.certs_file)
        if "autoridades" not in certs_db:
            certs_db["autoridades"] = {}
        
        certs_db["autoridades"][self.nombre] = {
            "tipo": "raiz" if self.es_raiz else "subordinada",
            "certificado": cert_pem,
            "fecha_creacion": datetime.now().isoformat(),
            "numero_serie": str(self.certificado.serial_number),
            "valido_desde": self.certificado.not_valid_before.isoformat(),
            "valido_hasta": self.certificado.not_valid_after.isoformat()
        }
        save_json(self.certs_file, certs_db)


    def _guardar_claves(self):
        """Guarda las claves privada y pública de la CA"""
        # Guardar clave privada (PROTEGIDA con contraseña)
        private_pem = self.clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        path_private = f"jsons\\certificados\\{self.nombre}_private.pem"
        with open(path_private, "w", encoding="utf-8") as f:
            f.write(private_pem)
        
        print(f"[PKI] Clave privada CA guardada en '{path_private}'")
        print(f"[PKI] ⚠️  ADVERTENCIA: Clave privada sin cifrar (solo para demostración)")
        
        # Guardar clave pública
        public_pem = self.clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        path_public = f"jsons\\certificados\\{self.nombre}_public.pem"
        with open(path_public, "w", encoding="utf-8") as f:
            f.write(public_pem)
        
        print(f"[PKI] Clave pública CA guardada en '{path_public}'")