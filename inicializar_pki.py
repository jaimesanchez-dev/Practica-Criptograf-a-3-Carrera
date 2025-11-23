from certificado import AutoridadCertificacion
from crear_archivos_autoridades import initialize_folder

def inicializar_pki():
    """Inicializa la infraestructura de clave pública (PKI) con múltiples ACs subordinadas"""
    
    print("\n=== Inicializando PKI ===\n")
    
    # Crear CA Raíz
    print("[1/4] Creando Autoridad de Certificación Raíz...")
    ca_raiz = AutoridadCertificacion(nombre="CA_Raiz", es_raiz=True)
    initialize_folder("CA_Raiz")
    ca_raiz.crear_certificado_raiz()
    
    # Crear AC Subordinada A
    print("\n[2/4] Creando Autoridad de Certificación Subordinada A...")
    ac_a = AutoridadCertificacion(
        nombre="AC_Subordinada_A",
        es_raiz=False,
        ca_superior=ca_raiz
    )
    initialize_folder("AC_Subordinada_A")
    ac_a.crear_certificado_subordinado()
    
    # Crear AC Subordinada B
    print("\n[3/4] Creando Autoridad de Certificación Subordinada B...")
    ac_b = AutoridadCertificacion(
        nombre="AC_Subordinada_B",
        es_raiz=False,
        ca_superior=ca_raiz
    )
    initialize_folder("AC_Subordinada_B")
    ac_b.crear_certificado_subordinado()
    
    print("\n[4/4] PKI inicializada correctamente")
    print("\nJerarquía creada:")
    print("  CA_Raiz (Autoridad Raíz)")
    print("  ├── AC_Subordinada_A")
    print("  └── AC_Subordinada_B")
    print("\nCada AC subordinada puede emitir certificados a usuarios\n")

if __name__ == "__main__":
    inicializar_pki()