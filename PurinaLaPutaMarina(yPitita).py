from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
import json
import os
import re
from datetime import datetime
from pathlib import Path

USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"

# Funciones JSON
def load_json(path):
    """Función que carga un archivo json"""
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path, obj):
    """Función que guarda un archivo json"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def initialize_files():
    """Función que inicializar los archivos json si no existen"""
    # Crear archivo de usuarios si no existe
    if not os.path.exists(USERS_FILE):
        save_json(USERS_FILE, {})
        print(f"Archivo '{USERS_FILE}' creado")

    if not os.path.exists(MESSAGES_FILE):
        save_json(MESSAGES_FILE, {"messages": []})
        print(f"Archivo '{MESSAGES_FILE}' creado")