import os
from funciones_json import load_json, save_json, initialize_files

# Crea archivo de claves si no existe
def initialize_folder(usuario):
    if not os.path.exists("json/{usuario}"):
        os.mkdir("jsons/{usuario}")

        save_json("json/{usuario}/claveprivada.json", {})
        print(f"Archivo 'json/{usuario}/claveprivada.json' creado")

        save_json("json/{usuario}/clavepublica.json", {})
        print(f"Archivo 'json/{usuario}/clavepublica.json' creado")
    
