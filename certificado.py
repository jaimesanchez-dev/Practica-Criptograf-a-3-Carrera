from cryptography import x509
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from funciones_json import save_json, load_json, initialize_files
import os
from crear_archivos_autoridades import save_clave_privada, save_clave_publica, cargar_clave_privada, cargar_clave_publica, save_certificado

from datetime import datetime, timedelta

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
        self._crear_carpetas()


    def _crear_carpetas(self):
        """Crea la estructura de carpetas para esta CA"""
        # Si es raíz: jsons/certificados/CA_Raiz/
        # Si es subordinada: jsons/certificados/CA_Raiz/CA_SubX/
            
        ca_path = self.determinar_raiz()
            
        # Crear todas las carpetas necesarias
        if not os.path.exists(ca_path):
            os.makedirs(ca_path)
            print(f"Carpeta creada: {ca_path}")
            
        # Crear carpeta de usuarios solo si es subordinada
        if not self.es_raiz:
            usuarios_path = f"{ca_path}\\usuarios"
            if not os.path.exists(usuarios_path):
                os.makedirs(usuarios_path)
                print(f"Carpeta de usuarios de {self.nombre} creada: {usuarios_path}")
    

    def determinar_raiz(self):
        if self.es_raiz:
            # CA Raíz va directamente en certificados/
            ca_path = f"jsons\\certificados\\{self.nombre}"
        else:
            # CA Subordinada va dentro de CA_Raiz/
            if not self.ca_superior:
                raise ValueError("CA subordinada no tiene una CA superior")
            ca_path = f"jsons\\certificados\\{self.ca_superior.nombre}\\{self.nombre}"

        return ca_path
    

    def guardar_clave_privada(self, clave_pem):
        """Función que guarda la clave privada"""

        ca_path = self.determinar_raiz() + "\\claveprivada.pem"
        
        with open(ca_path, "w", encoding="utf-8") as f:
            f.write(clave_pem)
        print(f"Clave privada guardada en '{ca_path}'")


    def guardar_clave_pública(self, clave_pem):
        """Función que guarda la clave privada"""

        ca_path = self.determinar_raiz() + "\\clavepublica.pem"
        
        with open(ca_path, "w", encoding="utf-8") as f:
            f.write(clave_pem)
        print(f"Clave privada guardada en '{ca_path}'")
    

    def cargar_clave_privada(self, autoridad):
        """Lee y devuelve la clave privada del autoridad desde su archivo .pem"""

        ca_path = self.determinar_raiz() + "\\claveprivada.pem"
        with open(ca_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        return private_key


    def cargar_clave_publica(self, autoridad):
        """Lee y devuelve la clave pública del autoridad desde su archivo .pem"""

        ca_path = self.determinar_raiz() + "\\claveprivada.pem"
        with open(ca_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        return public_key
        
        
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

        # Guardar en la carpeta de la CA
        ca_path = self.determinar_raiz()
        cert_file = f"{ca_path}\\certificado.pem"
        
        with open(cert_file, "w", encoding="utf-8") as f:
            f.write(cert_pem)
        print(f"Certificado guardado en '{cert_file}'")
        
        # También guardar en la raíz de certificados para compatibilidad
        cert_pem_raiz = f"jsons\\certificados\\{self.nombre}_cert.pem"
        with open(cert_pem_raiz, "w", encoding="utf-8") as f:
            f.write(cert_pem)
        
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

        # Guardar clave privada
        private_pem = self.clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        self.guardar_clave_privada(private_pem)
        
        # Guardar clave pública
        public_pem = self.clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        self.guardar_clave_pública(public_pem)


    def crear_certificado_raiz(self):
        """Crea un certificado autofirmado para la CA raíz"""
        if not self.es_raiz:
            raise ValueError("Solo las CA raíz pueden crear certificados autofirmados")
        
        # Generar claves
        self.generar_claves()
        
        # Crear el subject/issuer (para CA raíz son iguales)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.nombre),
        ])
        
        # Crear certificado autofirmado
        self.certificado = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.clave_publica)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=3650))  #10 años
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(self.clave_privada, hashes.SHA256()) #Poner aqui el cuerpo del mensaje /(Creo que seria mejor)
        )
        
        # Guardar certificado y claves
        self._guardar_certificado()
        self._guardar_claves()
        
        print(f"[PKI] Certificado raíz creado para '{self.nombre}'")
        return self.certificado
        
    def crear_certificado_subordinado(self):
        """Crea un certificado para una CA subordinada"""
        if self.es_raiz:
            raise ValueError("Este método es para CA subordinadas")
        
        if not self.ca_superior:
            raise ValueError("Debe especificarse la CA superior")
        
        # Generar claves
        self.generar_claves()
        
        # Crear el subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.nombre),
        ])
        
        # Crear certificado firmado por la CA superior
        self.certificado = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_superior.certificado.subject)
            .public_key(self.clave_publica)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=1825))  #5 años
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .sign(self.ca_superior.clave_privada, hashes.SHA256()) #Poner aqui el cuerpo del mensaje /(Creo que seria mejor)
        )
        
        # Guardar certificado y claves
        self._guardar_certificado()
        self._guardar_claves()
        
        print(f"[PKI] Certificado subordinado creado para '{self.nombre}'")
        return self.certificado

    def emitir_certificado_usuario(self, usuario, clave_publica_usuario):
        """Emite un certificado para un usuario final"""
        
        # Crear el subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, usuario),
        ])
        
        # Crear certificado firmado por esta CA
        cert_usuario = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificado.subject)
            .public_key(clave_publica_usuario)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now())
            .not_valid_after(datetime.now() + timedelta(days=365))  # 1 añito
            .sign(self.clave_privada, hashes.SHA256())
        )
        
        # Guardar el certificado del usuario   ----- Esto se puede pasar a un json de crear_usuarios.py
        cert_pem = cert_usuario.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()
        
        path = f"jsons\\{usuario}\\certificado.pem"
        with open(path, "w", encoding="utf-8") as f:
            f.write(cert_pem)
        
        print(f"[PKI] Certificado emitido para usuario '{usuario}'")
        
        # Guardar en JSON para referencia usando funciones_json
        certs_db = load_json(self.certs_file)
        if "usuarios" not in certs_db:
            certs_db["usuarios"] = {}
        
        certs_db["usuarios"][usuario] = {
            "certificado": cert_pem,
            "emisor": self.nombre,
            "fecha_emision": datetime.now().isoformat(),
            "numero_serie": str(cert_usuario.serial_number),
            "valido_desde": cert_usuario.not_valid_before.isoformat(),
            "valido_hasta": cert_usuario.not_valid_after.isoformat()
        }
        save_json(self.certs_file, certs_db)
        
        return cert_usuario
    
    def cargar_desde_archivos(self):
        """Carga el certificado y la clave privada desde archivos usando crear_archivos_autoridades"""
        # Cargar certificado
        cert_path = f"jsons\\certificados\\{self.nombre}_cert.pem"
        if os.path.exists(cert_path):
            with open(cert_path, "rb") as f:
                self.certificado = x509.load_pem_x509_certificate(f.read())
        
        # Cargar clave privada usando función de crear_archivos_autoridades
        try:
            self.clave_privada = cargar_clave_privada(self.nombre)
            self.clave_publica = self.clave_privada.public_key()
        except:
            pass


def cargar_certificado(path):
    """Carga un certificado desde un archivo PEM"""
    with open(path, "rb") as f:
        cert_data = f.read()
    return x509.load_pem_x509_certificate(cert_data)