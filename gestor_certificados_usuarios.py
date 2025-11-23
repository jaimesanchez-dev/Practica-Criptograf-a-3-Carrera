from certificado import AutoridadCertificacion, cargar_certificado
from crear_usuarios import cargar_clave_publica
from funciones_json import load_json
import os

# Importar funciones de crear_archivos_autoridades
import crear_archivos_autoridades as caa

class GestorCertificadosUsuarios:
    """Gestiona la emisión y verificación de certificados de usuarios"""
    
    def __init__(self):
        self.ca_subordinada = None
        self._cargar_ca_subordinada()
    
    def _cargar_ca_subordinada(self):
        """Carga la CA subordinada que emite certificados a usuarios"""
        try:
            # Intentar cargar certificado existente
            cert_path = "jsons\\certificados\\AC_Subordinada_cert.pem"
            if os.path.exists(cert_path):
                # Cargar la CA subordinada existente
                self.ca_subordinada = AutoridadCertificacion(
                    nombre="AC_Subordinada", 
                    es_raiz=False
                )
                
                # Usar la función cargar_desde_archivos que usa funciones de crear_archivos_autoridades
                self.ca_subordinada.cargar_desde_archivos()
                
                print("[PKI] CA Subordinada cargada correctamente")
            else:
                print("[PKI] Advertencia: No se encontró la CA. Ejecute inicializar_pki.py primero")
        except Exception as e:
            print(f"[PKI] Error al cargar CA: {e}")
            print("[PKI] Ejecute inicializar_pki.py para crear la infraestructura")
    
    def emitir_certificado_a_usuario(self, usuario):
        """Emite un certificado a un usuario registrado"""
        if not self.ca_subordinada:
            print("[PKI] Error: CA no inicializada")
            return False
        
        try:
            # Cargar la clave pública del usuario usando funciones de crear_usuarios
            clave_publica = cargar_clave_publica(usuario)
            
            # Emitir certificado
            cert = self.ca_subordinada.emitir_certificado_usuario(usuario, clave_publica)
            
            print(f"[PKI] ✓ Certificado emitido exitosamente para '{usuario}'")
            return True
        except Exception as e:
            print(f"[PKI] Error al emitir certificado: {e}")
            return False
    
    def verificar_certificado_usuario(self, usuario):
        """Verifica que un usuario tenga un certificado válido"""
        try:
            cert_path = f"jsons\\{usuario}\\certificado.pem"
            if not os.path.exists(cert_path):
                return False
            
            # Cargar certificado usando función de certificado.py
            cert = cargar_certificado(cert_path)
            
            # Verificar que no ha expirado
            from datetime import datetime
            ahora = datetime.now()
            
            if cert.not_valid_before <= ahora <= cert.not_valid_after:
                return True
            else:
                print(f"[PKI] Certificado de '{usuario}' ha expirado")
                return False
        except Exception as e:
            print(f"[PKI] Error al verificar certificado: {e}")
            return False
    
    def obtener_certificado_usuario(self, usuario):
        """Obtiene el certificado de un usuario"""
        try:
            cert_path = f"jsons\\{usuario}\\certificado.pem"
            if os.path.exists(cert_path):
                # Usar función de certificado.py
                return cargar_certificado(cert_path)
            else:
                print(f"[PKI] No se encontró certificado para '{usuario}'")
                return None
        except Exception as e:
            print(f"[PKI] Error al cargar certificado: {e}")
            return None