from certificado import AutoridadCertificacion, cargar_certificado
from crear_usuarios import cargar_clave_publica
from verificador_cadenas import VerificadorCadena
from funciones_json import load_json
import os
from cryptography import x509

class GestorCertificadosUsuarios:
    """Gestiona la emisión y verificación de certificados de usuarios con múltiples ACs"""
    
    def __init__(self):
        self.ca_raiz = None
        self.acs_subordinadas = {}  # Diccionario de ACs subordinadas
        self.verificador = VerificadorCadena()
        self._cargar_cas()
    
    def _cargar_cas(self):
        """Carga todas las CAs disponibles"""
        try:
            # Cargar CA Raíz
            cert_raiz_path = "jsons\\certificados\\CA_Raiz_cert.pem"
            if os.path.exists(cert_raiz_path):
                self.ca_raiz = AutoridadCertificacion(nombre="CA_Raiz", es_raiz=True)
                self.ca_raiz.cargar_desde_archivos()
                print("[PKI] CA Raíz cargada")
            
            # Cargar todas las ACs subordinadas disponibles
            cert_dir = "jsons\\certificados"
            if os.path.exists(cert_dir):
                for filename in os.listdir(cert_dir):
                    if filename.startswith("AC_Subordinada") and filename.endswith("_cert.pem"):
                        nombre_ac = filename.replace("_cert.pem", "")
                        
                        ac = AutoridadCertificacion(
                            nombre=nombre_ac,
                            es_raiz=False,
                            ca_superior=self.ca_raiz
                        )
                        ac.cargar_desde_archivos()
                        self.acs_subordinadas[nombre_ac] = ac
                        print(f"[PKI] {nombre_ac} cargada")
            
            if not self.acs_subordinadas:
                print("[PKI] Advertencia: No se encontraron ACs subordinadas. Ejecute inicializar_pki.py")
                
        except Exception as e:
            print(f"[PKI] Error al cargar CAs: {e}")
    
    def listar_acs_disponibles(self):
        """Lista todas las ACs subordinadas disponibles"""
        return list(self.acs_subordinadas.keys())
    
    def emitir_certificado_a_usuario(self, usuario, nombre_ac=None):
        """
        Emite un certificado a un usuario desde una AC específica
        Si no se especifica AC, usa la primera disponible
        """
        if not self.acs_subordinadas:
            print("[PKI] Error: No hay ACs subordinadas disponibles")
            return False
        
        # Si no se especifica AC, usar la primera disponible
        if nombre_ac is None:
            nombre_ac = list(self.acs_subordinadas.keys())[0]
        
        # Verificar que existe la AC
        if nombre_ac not in self.acs_subordinadas:
            print(f"[PKI] Error: AC '{nombre_ac}' no existe")
            print(f"[PKI] ACs disponibles: {', '.join(self.acs_subordinadas.keys())}")
            return False
        
        try:
            # Cargar la clave pública del usuario
            clave_publica = cargar_clave_publica(usuario)
            
            # Emitir certificado desde la AC especificada
            ac = self.acs_subordinadas[nombre_ac]
            cert = ac.emitir_certificado_usuario(usuario, clave_publica)
            
            print(f"[PKI] ✓ Certificado emitido para '{usuario}' por '{nombre_ac}'")
            return True
        except Exception as e:
            print(f"[PKI] Error al emitir certificado: {e}")
            return False
    
    def verificar_certificado_usuario(self, usuario):
        """
        Verifica la cadena completa de certificados del usuario
        Usuario → AC Subordinada → CA Raíz
        """
        valido, mensaje = self.verificador.verificar_cadena_completa(usuario)
        
        if not valido:
            print(f"[PKI] ✗ Certificado NO válido: {mensaje}")
        
        return valido
    
    def obtener_certificado_usuario(self, usuario):
        """Obtiene el certificado de un usuario"""
        try:
            cert_path = f"jsons\\{usuario}\\certificado.pem"
            if os.path.exists(cert_path):
                return cargar_certificado(cert_path)
            return None
        except Exception as e:
            print(f"[PKI] Error al cargar certificado: {e}")
            return None
    
    def obtener_info_certificado(self, usuario):
        """Obtiene información detallada del certificado de un usuario"""
        cert = self.obtener_certificado_usuario(usuario)
        if not cert:
            return None
        
        # Extraer el nombre de la AC emisora
        issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        nombre_ac = issuer_cn[0].value if issuer_cn else "Desconocida"
        
        return {
            "usuario": usuario,
            "emitido_por": nombre_ac,
            "valido_desde": cert.not_valid_before,
            "valido_hasta": cert.not_valid_after,
            "numero_serie": cert.serial_number
        }