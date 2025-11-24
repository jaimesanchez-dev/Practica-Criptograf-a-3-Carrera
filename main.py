from autenticacion import SistemaAutenticacion
from encriptado_hibrido import CifradoHibrido
from gestor_certificados_usuarios import GestorCertificadosUsuarios
from cryptography import x509
import getpass
import os

def menu_principal():
    print("====================================")
    print("   Sistema de Mensajería Segura  ")
    print("====================================\n")
    print("1. Registrar nuevo usuario")
    print("2. Iniciar sesión")
    print("3. Salir")

def menu_usuario(username):
    print(f"\n=== Menú del usuario: {username} ===")
    print("1. Enviar mensaje cifrado")
    print("2. Leer mis mensajes recibidos")
    print("3. Ver información de mi certificado")
    print("4. Verificar cadena completa de certificados")
    print("5. Cerrar sesión")

def main():
    # Verificar que existe la PKI
    if not os.path.exists("jsons\\certificados\\CA_Raiz_cert.pem"):
        print("[ADVERTENCIA] No se encontró la PKI.")
        print("Ejecute primero: python inicializar_pki.py\n")
        return
    
    autenticacion = SistemaAutenticacion()
    cripto = CifradoHibrido()
    gestor_certs = GestorCertificadosUsuarios()

    while True:
        menu_principal()
        opcion = input("Selecciona una opción: ").strip()

        # Registro
        if opcion == "1":
            usuario = input("Nombre de usuario: ").strip()
            contraseña = getpass.getpass("Contraseña: ").strip()

            if autenticacion.registrar_usuario(usuario, contraseña):
                # Mostrar ACs disponibles
                acs = gestor_certs.listar_acs_disponibles()
                print(f"\n[PKI] ACs disponibles: {', '.join(acs)}")
                
                ac_elegida = input(f"Elija AC para certificar (Enter para {acs[0]}): ").strip()
                if not ac_elegida:
                    ac_elegida = acs[0]
                
                print(f"\n[PKI] Emitiendo certificado desde '{ac_elegida}'...")

                gestor_certs.emitir_certificado_a_usuario(usuario, ac_elegida)
                
                print("\nUsuario registrado correctamente con certificado.\n")
            else:
                print("No se pudo registrar el usuario.")

        # Login
        elif opcion == "2":
            usuario = input("Usuario: ").strip()
            contraseña = getpass.getpass("Contraseña: ").strip()

            if autenticacion.login(usuario, contraseña):
                # Verificar cadena completa de certificados
                if gestor_certs.verificar_certificado_usuario(usuario):
                    print(f"\n¡Bienvenido, {usuario}!")
                    menu_sesion(autenticacion, cripto, gestor_certs, usuario)
                else:
                    print("\n[ERROR] Certificado inválido, expirado o cadena rota")

        # Salida
        elif opcion == "3":
            print("Saliendo del programa...")
            break

        else:
            print("Opción no válida. Intenta de nuevo.\n")

def menu_sesion(autenticacion, cripto, gestor_certs, usuario):
    while True:
        menu_usuario(usuario)
        opcion = input("Selecciona una opción: ").strip()

        # Enviar mensaje
        if opcion == "1":
            receptor = input("Destinatario: ").strip()
            
            if not autenticacion.existe_usuario(receptor):
                print(f"El usuario '{receptor}' no existe.")
                continue
            
            # Verificar cadena completa del receptor
            if not gestor_certs.verificar_certificado_usuario(receptor):
                print(f"El usuario '{receptor}' no tiene certificado válido.")
                continue
            
            mensaje = input("Mensaje: ").strip()
            cripto.encriptado_hibrido(usuario, receptor, mensaje)

        # Leer mensajes
        elif opcion == "2":
            cripto.desencriptado_hibrido(usuario)

        # Ver certificado
        elif opcion == "3":
            info = gestor_certs.obtener_info_certificado(usuario)
            if info:
                print(f"\n--- Certificado de {info['usuario']} ---")
                print(f"Emitido por: {info['emitido_por']}")
                print(f"Válido desde: {info['valido_desde']}")
                print(f"Válido hasta: {info['valido_hasta']}")
                print(f"Número de serie: {info['numero_serie']}\n")

        # Verificar cadena completa
        elif opcion == "4":
            gestor_certs.verificar_certificado_usuario(usuario)

        # Cerrar sesión
        elif opcion == "5":
            print(f"Sesión cerrada para {usuario}.\n")
            break

        else:
            print("Opción no válida. Intenta de nuevo.\n")

if __name__ == "__main__":
    main()
