from autenticacion import SistemaAutenticacion
from encriptacion import CifradoSimetrico

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
    print("3. Cerrar sesión")

def main():
    autenticacion = SistemaAutenticacion()
    cripto = CifradoSimetrico()

    while True:
        menu_principal()
        opcion = input("Selecciona una opción: ").strip()

        # Registro
        if opcion == "1":
            usuario = input("Nombre de usuario: ").strip()
            contraseña = input("Contraseña: ").strip()
            email = input("Email (opcional): ").strip() or None

            if autenticacion.registrar_usuario(usuario, contraseña, email):
                print("Usuario registrado correctamente.")
            else:
                print("No se pudo registrar el usuario.")

        # Login
        elif opcion == "2":
            usuario = input("Usuario: ").strip()
            contraseña = input("Contraseña: ").strip()

            if autenticacion.login(usuario, contraseña):
                print(f"\nBienvenido, {usuario}!")
                menu_sesion(autenticacion, cripto, usuario)
            else:
                print("Error de autenticación. Revisa tus credenciales.")

        # Salida
        elif opcion == "3":
            print("Saliendo del programa...")
            break

        else:
            print("Opción no válida. Intenta de nuevo.\n")

def menu_sesion(autenticacion, cripto, usuario):
    while True:
        menu_usuario(usuario)
        opcion = input("Selecciona una opción: ").strip()

        # Enviar mensaje
        if opcion == "1":
            receptor = input("Destinatario: ").strip()
            mensaje = input("Mensaje: ").strip()

            if not autenticacion.existe_usuario(receptor):
                print(f"El usuario '{receptor}' no existe.")
            else:
                cripto.encriptar_mensaje(usuario, receptor, mensaje)

        # Leer mensajes recibidos
        elif opcion == "2":
            cripto.desencriptar_mensaje(usuario)

        # Cerrar sesión
        elif opcion == "3":
            print(f"Sesión cerrada para {usuario}.\n")
            break

        else:
            print("Opción no válida. Intenta de nuevo.\n")

if __name__ == "__main__":
    main()
