from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from certificado import cargar_certificado
import os

class VerificadorCadena:
    """Verifica la cadena completa de certificados desde el usuario hasta la CA raíz"""
    
    def __init__(self):
        self.ca_raiz_cert = None
        self._cargar_ca_raiz()
    
    def _cargar_ca_raiz(self):
        """Carga el certificado de la CA raíz"""
        try:
            cert_path = "jsons\\certificados\\CA_Raiz_cert.pem"
            if os.path.exists(cert_path):
                self.ca_raiz_cert = cargar_certificado(cert_path)
                print("[VERIFICADOR] CA Raíz cargada para verificación")
            else:
                print("[VERIFICADOR] Error: No se encontró CA Raíz")
        except Exception as e:
            print(f"[VERIFICADOR] Error al cargar CA Raíz: {e}")
    
    def verificar_firma_certificado(self, cert_firmado, cert_emisor):
        """
        Verifica que cert_firmado fue realmente firmado por cert_emisor
        """
        try:
            # Obtener la clave pública del emisor
            clave_publica_emisor = cert_emisor.public_key()
            
            # Verificar la firma del certificado
            clave_publica_emisor.verify(
                cert_firmado.signature,
                cert_firmado.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_firmado.signature_hash_algorithm
            )
            return True
        except Exception as e:
            print(f"[VERIFICADOR] Error en verificación de firma: {e}")
            return False
    
    def verificar_fechas(self, cert):
        """Verifica que el certificado no esté expirado"""
        from datetime import datetime
        ahora = datetime.now()
        
        if not (cert.not_valid_before <= ahora <= cert.not_valid_after):
            print(f"[VERIFICADOR] ✗ Certificado expirado")
            return False
        return True
    
    def obtener_nombre_ac_emisora(self, cert_usuario):
        """Extrae el nombre de la AC que emitió el certificado del usuario"""
        # El emisor está en el campo issuer del certificado
        issuer_cn = cert_usuario.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if issuer_cn:
            return issuer_cn[0].value
        return None
    
    def cargar_certificado_ac(self, nombre_ac):
        """Carga el certificado de una AC subordinada por su nombre"""
        try:
            cert_path = f"jsons\\certificados\\{nombre_ac}_cert.pem"
            if os.path.exists(cert_path):
                return cargar_certificado(cert_path)
            else:
                print(f"[VERIFICADOR] No se encontró certificado de {nombre_ac}")
                return None
        except Exception as e:
            print(f"[VERIFICADOR] Error al cargar {nombre_ac}: {e}")
            return None
    
    def verificar_cadena_completa(self, usuario):
        """
        Verifica la cadena completa de certificados:
        Usuario → AC Subordinada → CA Raíz
        
        Retorna: (es_valido, detalles)
        """
        if not self.ca_raiz_cert:
            return False, "CA Raíz no disponible"
        
        print(f"\n[VERIFICADOR] === Verificando cadena de certificados para '{usuario}' ===\n")
        
        # Paso 1: Cargar certificado del usuario
        cert_usuario_path = f"jsons\\{usuario}\\certificado.pem"
        if not os.path.exists(cert_usuario_path):
            return False, f"No existe certificado para {usuario}"
        
        cert_usuario = cargar_certificado(cert_usuario_path)
        print(f"[1/3] Certificado de usuario '{usuario}' cargado")
        
        # Verificar fechas del certificado del usuario
        if not self.verificar_fechas(cert_usuario):
            return False, "Certificado de usuario expirado"
        print(f"      ✓ Fechas válidas")
        
        # Paso 2: Identificar y cargar el certificado de la AC emisora
        nombre_ac_emisora = self.obtener_nombre_ac_emisora(cert_usuario)
        if not nombre_ac_emisora:
            return False, "No se pudo identificar AC emisora"
        
        print(f"\n[2/3] Certificado emitido por: '{nombre_ac_emisora}'")
        
        cert_ac_subordinada = self.cargar_certificado_ac(nombre_ac_emisora)
        if not cert_ac_subordinada:
            return False, f"No se pudo cargar certificado de {nombre_ac_emisora}"
        
        # Verificar que la AC subordinada firmó el certificado del usuario
        if not self.verificar_firma_certificado(cert_usuario, cert_ac_subordinada):
            return False, f"La firma del certificado de usuario NO es válida (no firmado por {nombre_ac_emisora})"
        print(f"      ✓ Firma del certificado de usuario verificada correctamente")
        
        # Verificar fechas de la AC subordinada
        if not self.verificar_fechas(cert_ac_subordinada):
            return False, f"Certificado de {nombre_ac_emisora} expirado"
        print(f"      ✓ Fechas válidas")
        
        # Paso 3: Verificar que la CA Raíz firmó el certificado de la AC subordinada
        print(f"\n[3/3] Verificando firma de CA_Raiz sobre '{nombre_ac_emisora}'")
        
        if not self.verificar_firma_certificado(cert_ac_subordinada, self.ca_raiz_cert):
            return False, f"La firma de {nombre_ac_emisora} NO es válida (no firmada por CA_Raiz)"
        print(f"      ✓ Firma del certificado de AC subordinada verificada correctamente")
        
        # Verificar que la CA Raíz está autofirmada correctamente
        if not self.verificar_firma_certificado(self.ca_raiz_cert, self.ca_raiz_cert):
            return False, "CA Raíz no está autofirmada correctamente"
        print(f"      ✓ CA_Raiz autofirmada correctamente")
        
        # Verificar fechas de CA Raíz
        if not self.verificar_fechas(self.ca_raiz_cert):
            return False, "Certificado de CA Raíz expirado"
        
        print(f"\n[RESULTADO] ✓✓✓ Cadena de certificados VÁLIDA ✓✓✓")
        print(f"            {usuario} ← {nombre_ac_emisora} ← CA_Raiz\n")
        
        return True, f"Cadena válida: {usuario} ← {nombre_ac_emisora} ← CA_Raiz"