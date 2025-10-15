import os


def initialize_folder(usuario):
    folder = f"jsons\\{usuario}"
    if not os.path.exists(folder):
        os.makedirs(folder)
        print(f"Carpeta '{folder}' creada")

def save_clave_privada(usuario, clave_pem):
    path = f"jsons\\{usuario}\\claveprivada.pem"
    with open(path, "w", encoding="utf-8") as f:
        f.write(clave_pem)
    print(f"Clave privada guardada en '{path}'")

def save_clave_publica(usuario, clave_pem):
    path = f"jsons\\{usuario}\\clavepublica.pem"
    with open(path, "w", encoding="utf-8") as f:
        f.write(clave_pem)
    print(f"Clave pública guardada en '{path}'")