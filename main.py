from autenticacion import AuthenticationSystem
from encriptacion import CifradoSimetrico

def menu_principal():
    print("====================================")
    print("   🔐 Sistema de Mensajería Segura  ")
    print("====================================\n")

    print("1. Registrar nuevo usuario")
    print("2. Iniciar sesión")
    print("3. Salir")

def menu_usuario(username):
    print(f"\n=== Menú del usuario: {username} ===")
    print("1. Enviar mensaje cifrado")
    print("2. Leer mis mensajes recibidos")
    print("3. Cerrar sesión")

def main():
    auth = AuthenticationSystem()
    crypto = CifradoSimetrico()

    while True:
        menu_principal()
        opcion = input("Selecciona una opción: ").strip()

        # Registro
        if opcion == "1":
            username = input("Nombre de usuario: ").strip()
            password = input("Contraseña: ").strip()
            email = input("Email (opcional): ").strip() or None

            if auth.register_user(username, password, email):
                print("✅ Usuario registrado correctamente.")
            else:
                print("❌ No se pudo registrar el usuario.")

        # Login
        elif opcion == "2":
            username = input("Usuario: ").strip()
            password = input("Contraseña: ").strip()

            if auth.login(username, password):
                print(f"\n👋 Bienvenido, {username}!")
                menu_sesion(auth, crypto, username)
            else:
                print("❌ Error de autenticación. Revisa tus credenciales.")

        # Salida
        elif opcion == "3":
            print("👋 Saliendo del programa...")
            break

        else:
            print("Opción no válida. Intenta de nuevo.\n")

def menu_sesion(auth, crypto, username):
    while True:
        menu_usuario(username)
        opcion = input("Selecciona una opción: ").strip()

        # Enviar mensaje
        if opcion == "1":
            recipient = input("Destinatario: ").strip()
            mensaje = input("Mensaje: ").strip()

            if not auth.user_exists(recipient):
                print(f"❌ El usuario '{recipient}' no existe.")
            else:
                crypto.encriptar_mensaje(username, recipient, mensaje)

        # Leer mensajes recibidos
        elif opcion == "2":
            crypto.desencriptar_mensaje(username)

        # Cerrar sesión
        elif opcion == "3":
            print(f"👋 Sesión cerrada para {username}.\n")
            break

        else:
            print("Opción no válida. Intenta de nuevo.\n")

if __name__ == "__main__":
    main()
