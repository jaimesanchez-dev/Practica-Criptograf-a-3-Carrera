from certificado import AutoridadCertificacion, cargar_certificado
from verificador_cadenas import VerificadorCadena
from firmas import firma_mensaje, verificar_firma
from crear_usuarios import cargar_clave_privada, cargar_clave_publica
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
from datetime import datetime, timezone, timedelta

class TestPKI:
    """Clase para realizar todas las pruebas de PKI y Firmas"""
    
    def __init__(self):
        self.ca_raiz = None
        self.ac_a = None
        self.ac_b = None
        self.resultados = []
        self.tests_pasados = 0
        self.tests_fallados = 0
    
    def log_test(self, nombre, pasado, mensaje=""):
        """Registra el resultado de un test"""
        estado = "✓ PASS" if pasado else "✗ FAIL"
        resultado = f"{estado} | {nombre}"
        if mensaje:
            resultado += f" | {mensaje}"
        self.resultados.append(resultado)
        
        if pasado:
            self.tests_pasados += 1
            print(f"  {estado} {nombre}")
        else:
            self.tests_fallados += 1
            print(f"  {estado} {nombre} - {mensaje}")
    
    def mostrar_resumen(self):
        """Muestra el resumen final de las pruebas"""
        print("\n" + "="*70)
        print("  RESUMEN DE PRUEBAS")
        print("="*70)
        print(f"\nTotal de pruebas: {self.tests_pasados + self.tests_fallados}")
        print(f"✓ Pruebas pasadas: {self.tests_pasados}")
        print(f"✗ Pruebas falladas: {self.tests_fallados}")
        
        if self.tests_fallados == 0:
            print("\n🎉 ¡TODAS LAS PRUEBAS PASARON!")
        else:
            print(f"\n⚠️  {self.tests_fallados} pruebas fallaron")
            print("\nPruebas falladas:")
            for resultado in self.resultados:
                if "FAIL" in resultado:
                    print(f"  - {resultado}")
    
    # ========================================
    # PRUEBAS DE ESTRUCTURA PKI
    # ========================================
    
    def test_1_estructura_carpetas(self):
        """Test 1: Verificar estructura de carpetas PKI"""
        print("\n[TEST 1] Verificando estructura de carpetas...")
        
        # Verificar CA Raíz
        existe_raiz = os.path.exists("jsons\\certificados\\CA_Raiz")
        self.log_test(
            "1.1 - Carpeta CA_Raiz existe",
            existe_raiz
        )
        
        # Verificar AC Subordinada A
        existe_sub_a = os.path.exists("jsons\\certificados\\CA_Raiz\\AC_Subordinada_A")
        self.log_test(
            "1.2 - Carpeta AC_Subordinada_A existe",
            existe_sub_a
        )
        
        # Verificar AC Subordinada B
        existe_sub_b = os.path.exists("jsons\\certificados\\CA_Raiz\\AC_Subordinada_B")
        self.log_test(
            "1.3 - Carpeta AC_Subordinada_B existe",
            existe_sub_b
        )
        
        # Verificar carpetas de usuarios
        existe_usuarios_a = os.path.exists("jsons\\certificados\\CA_Raiz\\AC_Subordinada_A\\usuarios")
        self.log_test(
            "1.4 - Carpeta usuarios de AC_A existe",
            existe_usuarios_a
        )
        
        existe_usuarios_b = os.path.exists("jsons\\certificados\\CA_Raiz\\AC_Subordinada_B\\usuarios")
        self.log_test(
            "1.5 - Carpeta usuarios de AC_B existe",
            existe_usuarios_b
        )
    
    def test_2_archivos_ca_raiz(self):
        """Test 2: Verificar archivos de CA Raíz"""
        print("\n[TEST 2] Verificando archivos de CA Raíz...")
        
        base = "jsons\\certificados\\CA_Raiz"
        
        # Verificar certificado
        existe_cert = os.path.exists(f"{base}\\certificado.pem")
        self.log_test(
            "2.1 - Certificado CA_Raiz existe",
            existe_cert
        )
        
        # Verificar clave privada
        existe_privada = os.path.exists(f"{base}\\claveprivada.pem")
        self.log_test(
            "2.2 - Clave privada CA_Raiz existe",
            existe_privada
        )
        
        # Verificar clave pública
        existe_publica = os.path.exists(f"{base}\\clavepublica.pem")
        self.log_test(
            "2.3 - Clave pública CA_Raiz existe",
            existe_publica
        )
    
    def test_3_archivos_ca_subordinadas(self):
        """Test 3: Verificar archivos de CAs Subordinadas"""
        print("\n[TEST 3] Verificando archivos de CAs Subordinadas...")
        
        for nombre_ac in ["AC_Subordinada_A", "AC_Subordinada_B"]:
            base = f"jsons\\certificados\\CA_Raiz\\{nombre_ac}"
            
            existe_cert = os.path.exists(f"{base}\\certificado.pem")
            self.log_test(
                f"3.{nombre_ac[-1]} - Certificado {nombre_ac} existe",
                existe_cert
            )
            
            existe_privada = os.path.exists(f"{base}\\claveprivada.pem")
            self.log_test(
                f"3.{nombre_ac[-1]}.1 - Clave privada {nombre_ac} existe",
                existe_privada
            )
    
    # ========================================
    # PRUEBAS DE CERTIFICADOS
    # ========================================
    
    def test_4_certificado_raiz_autofirmado(self):
        """Test 4: Verificar que CA Raíz es autofirmada"""
        print("\n[TEST 4] Verificando certificado raíz autofirmado...")
        
        try:
            cert = cargar_certificado("jsons\\certificados\\CA_Raiz\\certificado.pem")
            
            # Subject debe ser igual a Issuer (autofirmado)
            es_autofirmado = cert.subject == cert.issuer
            self.log_test(
                "4.1 - CA_Raiz es autofirmada (Subject == Issuer)",
                es_autofirmado,
                f"Subject: {cert.subject}, Issuer: {cert.issuer}"
            )
            
            # Debe tener extensión CA=TRUE
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                ).value
                es_ca = basic_constraints.ca
                self.log_test(
                    "4.2 - CA_Raiz tiene BasicConstraints CA=TRUE",
                    es_ca
                )
            except:
                self.log_test(
                    "4.2 - CA_Raiz tiene BasicConstraints CA=TRUE",
                    False,
                    "No tiene extensión BasicConstraints"
                )
            
            # Verificar fechas de validez
            ahora = datetime.now(timezone.utc)
            es_valido = cert.not_valid_before_utc <= ahora <= cert.not_valid_after_utc
            self.log_test(
                "4.3 - CA_Raiz tiene fechas válidas",
                es_valido,
                f"Válido desde {cert.not_valid_before_utc} hasta {cert.not_valid_after_utc}"
            )
            
        except Exception as e:
            self.log_test(
                "4.1 - Cargar certificado CA_Raiz",
                False,
                str(e)
            )
    
    def test_5_certificados_subordinados_firmados(self):
        """Test 5: Verificar que CAs subordinadas están firmadas por Raíz"""
        print("\n[TEST 5] Verificando certificados subordinados...")
        
        try:
            cert_raiz = cargar_certificado("jsons\\certificados\\CA_Raiz\\certificado.pem")
            
            for nombre_ac in ["AC_Subordinada_A", "AC_Subordinada_B"]:
                try:
                    cert_sub = cargar_certificado(
                        f"jsons\\certificados\\CA_Raiz\\{nombre_ac}\\certificado.pem"
                    )
                    
                    # Issuer debe ser CA_Raiz
                    issuer_cn = cert_sub.issuer.get_attributes_for_oid(
                        x509.oid.NameOID.COMMON_NAME
                    )[0].value
                    
                    es_correcto = issuer_cn == "CA_Raiz"
                    self.log_test(
                        f"5.{nombre_ac[-1]} - {nombre_ac} firmada por CA_Raiz",
                        es_correcto,
                        f"Issuer: {issuer_cn}"
                    )
                    
                    # Verificar firma criptográfica
                    verificador = VerificadorCadena()
                    firma_valida = verificador.verificar_firma_certificado(cert_sub, cert_raiz)
                    self.log_test(
                        f"5.{nombre_ac[-1]}.1 - Firma criptográfica de {nombre_ac} válida",
                        firma_valida
                    )
                    
                except Exception as e:
                    self.log_test(
                        f"5.{nombre_ac[-1]} - Verificar {nombre_ac}",
                        False,
                        str(e)
                    )
        except Exception as e:
            self.log_test(
                "5.0 - Cargar certificado raíz",
                False,
                str(e)
            )
    
    def test_6_verificacion_cadena_completa(self):
        """Test 6: Verificar cadenas de certificados completas"""
        print("\n[TEST 6] Verificando cadenas de certificados...")
        
        # Buscar usuarios existentes
        usuarios = []
        if os.path.exists("jsons"):
            for item in os.listdir("jsons"):
                item_path = os.path.join("jsons", item)
                if os.path.isdir(item_path) and item not in ["certificados"]:
                    cert_path = f"jsons\\{item}\\{item}_cert.pem"
                    if os.path.exists(cert_path):
                        usuarios.append(item)
        
        if not usuarios:
            self.log_test(
                "6.0 - Buscar usuarios para verificar",
                False,
                "No hay usuarios registrados"
            )
            return
        
        verificador = VerificadorCadena()
        
        for usuario in usuarios[:3]:  # Probar máximo 3 usuarios
            valido, mensaje = verificador.verificar_cadena_completa(usuario)
            self.log_test(
                f"6.{usuarios.index(usuario)+1} - Cadena completa de '{usuario}' válida",
                valido,
                mensaje if not valido else ""
            )
    
    # ========================================
    # PRUEBAS DE FIRMAS DIGITALES
    # ========================================
    
    def test_7_firma_y_verificacion_basica(self):
        """Test 7: Firmar y verificar un mensaje simple"""
        print("\n[TEST 7] Probando firmas digitales básicas...")
        
        try:
            # Generar par de claves temporal
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            
            mensaje = b"Mensaje de prueba para firma digital"
            
            # Firmar
            try:
                firma = firma_mensaje(private_key, mensaje)
                self.log_test(
                    "7.1 - Firmar mensaje con clave privada",
                    True
                )
            except Exception as e:
                self.log_test(
                    "7.1 - Firmar mensaje con clave privada",
                    False,
                    str(e)
                )
                return
            
            # Verificar con clave pública correcta
            es_valida = verificar_firma(public_key, mensaje, firma)
            self.log_test(
                "7.2 - Verificar firma con clave pública correcta",
                es_valida
            )
            
            # Verificar con mensaje alterado (debe fallar)
            mensaje_alterado = b"Mensaje alterado maliciosamente"
            es_invalida = not verificar_firma(public_key, mensaje_alterado, firma)
            self.log_test(
                "7.3 - Rechazar firma con mensaje alterado",
                es_invalida
            )
            
            # Verificar con clave pública incorrecta (debe fallar)
            otra_key = rsa.generate_private_key(65537, 2048).public_key()
            es_invalida = not verificar_firma(otra_key, mensaje, firma)
            self.log_test(
                "7.4 - Rechazar firma con clave pública incorrecta",
                es_invalida
            )
            
        except Exception as e:
            self.log_test(
                "7.0 - Setup de prueba de firmas",
                False,
                str(e)
            )
    
    def test_8_firma_con_certificado_usuario(self):
        """Test 8: Firmar usando clave de usuario con certificado"""
        print("\n[TEST 8] Probando firmas con certificados de usuario...")
        
        # Buscar un usuario existente
        usuarios = []
        if os.path.exists("jsons"):
            for item in os.listdir("jsons"):
                item_path = os.path.join("jsons", item)
                if os.path.isdir(item_path) and item not in ["certificados"]:
                    cert_path = f"jsons\\{item}\\{item}_cert.pem"
                    key_path = f"jsons\\{item}\\claveprivada.pem"
                    if os.path.exists(cert_path) and os.path.exists(key_path):
                        usuarios.append(item)
        
        if not usuarios:
            self.log_test(
                "8.0 - Buscar usuario con certificado",
                False,
                "No hay usuarios con certificados"
            )
            return
        
        usuario = usuarios[0]
        
        try:
            # Cargar certificado
            cert = cargar_certificado(f"jsons\\{usuario}\\{usuario}_cert.pem")
            clave_publica_cert = cert.public_key()
            
            # Cargar clave privada (requiere contraseña)
            # Para pruebas, asumimos que hay una función que puede cargar sin contraseña
            # o que tenemos una contraseña de prueba
            self.log_test(
                "8.1 - Cargar certificado de usuario",
                True,
                f"Usuario: {usuario}"
            )
            
            # Verificar que la clave pública del certificado coincide
            try:
                clave_publica_file = cargar_clave_publica(usuario)
                
                # Comparar claves públicas (serializadas)
                pub_cert = clave_publica_cert.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                pub_file = clave_publica_file.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                coinciden = pub_cert == pub_file
                self.log_test(
                    "8.2 - Clave pública del certificado coincide con archivo",
                    coinciden
                )
                
            except Exception as e:
                self.log_test(
                    "8.2 - Cargar y comparar claves públicas",
                    False,
                    str(e)
                )
            
        except Exception as e:
            self.log_test(
                "8.1 - Cargar certificado de usuario",
                False,
                str(e)
            )
    
    def test_9_integridad_firma_en_mensajes(self):
        """Test 9: Verificar integridad de firmas en sistema de mensajes"""
        print("\n[TEST 9] Verificando integridad de firmas en mensajes...")
        
        try:
            # Generar mensaje de prueba firmado
            private_key = rsa.generate_private_key(65537, 2048)
            public_key = private_key.public_key()
            
            mensaje_original = b"Mensaje importante cifrado"
            firma = firma_mensaje(private_key, mensaje_original)
            
            # Simular alteración del mensaje
            mensaje_alterado = b"Mensaje importante alterado"
            
            # La firma del mensaje original NO debe validar con mensaje alterado
            firma_valida_original = verificar_firma(public_key, mensaje_original, firma)
            firma_invalida_alterado = not verificar_firma(public_key, mensaje_alterado, firma)
            
            self.log_test(
                "9.1 - Firma válida para mensaje original",
                firma_valida_original
            )
            
            self.log_test(
                "9.2 - Firma inválida para mensaje alterado",
                firma_invalida_alterado
            )
            
            # Simular alteración de la firma
            firma_alterada = bytearray(firma)
            firma_alterada[0] = (firma_alterada[0] + 1) % 256
            firma_alterada = bytes(firma_alterada)
            
            firma_invalida = not verificar_firma(public_key, mensaje_original, firma_alterada)
            self.log_test(
                "9.3 - Rechazar firma alterada",
                firma_invalida
            )
            
        except Exception as e:
            self.log_test(
                "9.0 - Prueba de integridad de firmas",
                False,
                str(e)
            )
    
    # ========================================
    # PRUEBAS DE CASOS DE ERROR
    # ========================================
    
    def test_10_certificado_inexistente(self):
        """Test 10: Manejar certificados inexistentes"""
        print("\n[TEST 10] Probando manejo de errores...")
        
        verificador = VerificadorCadena()
        
        # Verificar usuario que no existe
        valido, mensaje = verificador.verificar_cadena_completa("usuario_inexistente_xyz")
        
        self.log_test(
            "10.1 - Rechazar certificado de usuario inexistente",
            not valido
        )
    
    def test_11_verificacion_certificado_desde_pem(self):
        """Test 11: Verificar certificado desde contenido PEM"""
        print("\n[TEST 11] Verificando certificados desde PEM...")
        
        # Buscar usuario
        usuarios = []
        if os.path.exists("jsons"):
            for item in os.listdir("jsons"):
                item_path = os.path.join("jsons", item)
                if os.path.isdir(item_path) and item not in ["certificados"]:
                    cert_path = f"jsons\\{item}\\{item}_cert.pem"
                    if os.path.exists(cert_path):
                        usuarios.append(item)
        
        if not usuarios:
            self.log_test(
                "11.0 - Buscar usuario para prueba",
                False,
                "No hay usuarios"
            )
            return
        
        usuario = usuarios[0]
        
        try:
            # Cargar contenido PEM
            cert_path = f"jsons\\{usuario}\\{usuario}_cert.pem"
            with open(cert_path, "r") as f:
                cert_pem = f.read()
            
            verificador = VerificadorCadena()
            
            # Verificar con nombre correcto
            valido, mensaje = verificador.verificar_certificado_desde_pem(cert_pem, usuario)
            self.log_test(
                f"11.1 - Verificar certificado PEM con nombre correcto ({usuario})",
                valido
            )
            
            # Verificar con nombre incorrecto (debe fallar)
            invalido, mensaje = verificador.verificar_certificado_desde_pem(cert_pem, "nombre_incorrecto")
            self.log_test(
                "11.2 - Rechazar certificado PEM con nombre incorrecto",
                not invalido
            )
            
        except Exception as e:
            self.log_test(
                "11.0 - Cargar y verificar PEM",
                False,
                str(e)
            )
    
    # ========================================
    # PRUEBAS DE PROPIEDADES DE CERTIFICADOS
    # ========================================
    
    def test_12_propiedades_certificados_usuario(self):
        """Test 12: Verificar propiedades de certificados de usuario"""
        print("\n[TEST 12] Verificando propiedades de certificados de usuario...")
        
        # Buscar usuario
        usuarios = []
        if os.path.exists("jsons"):
            for item in os.listdir("jsons"):
                item_path = os.path.join("jsons", item)
                if os.path.isdir(item_path) and item not in ["certificados"]:
                    cert_path = f"jsons\\{item}\\{item}_cert.pem"
                    if os.path.exists(cert_path):
                        usuarios.append(item)
        
        if not usuarios:
            self.log_test(
                "12.0 - Buscar usuario",
                False,
                "No hay usuarios"
            )
            return
        
        usuario = usuarios[0]
        
        try:
            cert = cargar_certificado(f"jsons\\{usuario}\\{usuario}_cert.pem")
            
            # Verificar que NO es CA
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                ).value
                no_es_ca = not basic_constraints.ca
                self.log_test(
                    "12.1 - Usuario tiene BasicConstraints CA=FALSE",
                    no_es_ca
                )
            except:
                self.log_test(
                    "12.1 - Usuario tiene BasicConstraints CA=FALSE",
                    True,
                    "No tiene extensión (por defecto no es CA)"
                )
            
            # Verificar Common Name
            cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            cn_correcto = cn_attrs[0].value == usuario if cn_attrs else False
            self.log_test(
                f"12.2 - Common Name del certificado es '{usuario}'",
                cn_correcto
            )
            
            # Verificar emisor
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            es_subordinada = "Subordinada" in issuer_cn[0].value if issuer_cn else False
            self.log_test(
                "12.3 - Certificado emitido por CA Subordinada",
                es_subordinada,
                f"Emisor: {issuer_cn[0].value if issuer_cn else 'Desconocido'}"
            )
            
        except Exception as e:
            self.log_test(
                "12.0 - Cargar certificado de usuario",
                False,
                str(e)
            )
    
    # ========================================
    # MÉTODO PRINCIPAL
    # ========================================
    
    def ejecutar_todas_las_pruebas(self):
        """Ejecuta todas las pruebas"""
        print("\n" + "="*70)
        print("  SUITE DE PRUEBAS - PKI Y FIRMAS DIGITALES")
        print("="*70)
        print("\nEjecutando pruebas exhaustivas del sistema...")
        
        # Pruebas de estructura
        self.test_1_estructura_carpetas()
        self.test_2_archivos_ca_raiz()
        self.test_3_archivos_ca_subordinadas()
        
        # Pruebas de certificados
        self.test_4_certificado_raiz_autofirmado()
        self.test_5_certificados_subordinados_firmados()
        self.test_6_verificacion_cadena_completa()
        
        # Pruebas de firmas
        self.test_7_firma_y_verificacion_basica()
        self.test_8_firma_con_certificado_usuario()
        self.test_9_integridad_firma_en_mensajes()
        
        # Pruebas de errores
        self.test_10_certificado_inexistente()
        self.test_11_verificacion_certificado_desde_pem()
        
        # Pruebas de propiedades
        self.test_12_propiedades_certificados_usuario()
        
        # Mostrar resumen
        self.mostrar_resumen()


# ============================================
# EJECUTAR PRUEBAS
# ============================================

if __name__ == "__main__":
    tester = TestPKI()
    tester.ejecutar_todas_las_pruebas()