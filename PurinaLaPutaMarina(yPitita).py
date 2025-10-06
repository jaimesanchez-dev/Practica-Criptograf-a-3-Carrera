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
    """Función que inicializa los archivos json si no existen"""
    # Crea archivo de usuarios si no existe
    if not os.path.exists(USERS_FILE):
        save_json(USERS_FILE, {})
        print(f"Archivo '{USERS_FILE}' creado")

    # Crea archivo de mensajes si no existe
    if not os.path.exists(MESSAGES_FILE):
        save_json(MESSAGES_FILE, {"messages": []})
        print(f"Archivo '{MESSAGES_FILE}' creado")


class AuthenticationSystem:
    """Gestiona el registro y autenticación de usuarios"""
    
    def __init__(self, users_file = USERS_FILE):
        """Inicializa el sistema de autenticación con Argon2"""
        self.users_file = users_file
        
        # Inicializar archivos si no existen
        initialize_files()

        self.ph = PasswordHasher()
        
        self.users_db = load_json(self.users_file)
        
        print("Sistema de Autenticación inicializado\n")
    
    def _validate_username(self, username):
        """Valida el formato del nombre de usuario"""
        
        # Si no hay nombre de usuario, devuelve False
        if not username or len(username) == 0:
            print("El nombre de usuario no puede estar vacío")
            return False
        
        # Si el nombre de usuario tiene menos de 3 caracteres, devuelve False
        if len(username) < 3:
            print("El nombre de usuario debe tener al menos 3 caracteres")
            return False
        
        # Si el nombre de usuario tiene más de 20 caracteres, devuelve False
        if len(username) > 20:
            print("El nombre de usuario no puede exceder 20 caracteres")
            return False
        
        # Si el nombre de usuario no contiene únicamente letras, números, y guión bajo devuelve, False
        if not re.match(r'^[A-Z0-9_]', username):
            print("El nombre de usuario solo puede contener letras, números y guiones bajos")
            return False
        
        # En los demás casos devuelve True
        return True
    
    def _validate_password_strength(self, password):
        """Valida que el usuario tenga una contraseña segura"""

        # Si no introduce una contraseña, devuelve False
        if not password or len(password) == 0:
            print("La contraseña no puede estar vacía")
            return False
        
        # Si la contraseña tiene una longitud inferior a 8 caracteres, devuelve False
        if len(password) < 8:
            print("La contraseña debe tener al menos 8 caracteres")
            return False
        
        # Si la contraseña no contiene una mayúscula, devuelve False
        if not re.search(r'[A-Z]', password):
            print("La contraseña debe contener al menos una mayúscula")
            return False
        
        # Si la contraseña no contiene una minúscula, devuelve False
        if not re.search(r'[a-z]', password):
            print("La contraseña debe contener al menos una minúscula")
            return False
        
        # Si la contraseña no contiene un número, devuelve False
        if not re.search(r'[0-9]', password):
            print("La contraseña debe contener al menos un número")
            return False
        
        # Si la contraseña no contiene un carácter especial, devuelve False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]]', password):
            print("La contraseña debe contener al menos un carácter especial")
            return False
        
        return True
    
    def register_user(self, username, password, email=None):
        """Registra un nuevo usuario en el sistema"""

        # Validar nombre de usuario
        valid = self._validate_username(username)
        if not valid:
            return False
        
        # Verificar si el usuario ya existe
        if username in self.users_db:
            print(f"Usuario '{username}' ya existe")
            return False
        
        # Validar seguridad de la contraseña
        valid = self._validate_password_strength(password)
        if not valid:
            return False
        
        # Hacer hash a la contraseña usando Argon2
        try:
            password_hash = self.ph.hash(password)
        except Exception as e:
            print(f"Error al hacer hash a la contraseña: {e}")
            return False
        
        # Crear registro de usuario
        self.users_db[username] = {
            'hash': password_hash,
            'email': email,
            'created_at': datetime.now().isoformat(),
            'last_login': None
        }
        
        # Guardar el json con el nuevo usuario
        save_json(self.users_file, self.users_db)
        
        print("Usuario registrado correctamente\n")
        print(f"   - Usuario: {username}\n")
        
        return True
    
    def login(self, username, password):
        """
        Autentica un usuario verificando sus credenciales
        (Alias de authenticate_user)
        
        Args:
            username: Nombre de usuario
            password: Contraseña en texto plano
            
        Returns:
            tuple: (bool, str) - (éxito, mensaje)
        """
        return self.authenticate_user(username, password)
    
    def authenticate_user(self, username, password):
        """
        Autentica un usuario verificando sus credenciales con Argon2
        
        Args:
            username: Nombre de usuario
            password: Contraseña en texto plano
            
        Returns:
            tuple: (bool, str) - (éxito, mensaje)
        """
        # Recargar usuarios del archivo (por si hubo cambios externos)
        self.users_db = load_json(self.users_file)
        
        # Verificar si el usuario existe
        if username not in self.users_db:
            print(f"❌ Usuario '{username}' no existe")
            return False, "Usuario no existe"
        
        # Obtener el hash almacenado
        stored_hash = self.users_db[username]['hash']
        
        # Verificar la contraseña con Argon2
        try:
            self.ph.verify(stored_hash, password)
            
            # Si necesita rehashing (parámetros actualizados), lo hace automáticamente
            if self.ph.check_needs_rehash(stored_hash):
                print("ℹ️  Actualizando hash con nuevos parámetros...")
                self.users_db[username]['hash'] = self.ph.hash(password)
            
            # Actualizar último login
            self.users_db[username]['last_login'] = datetime.now().isoformat()
            save_json(self.users_file, self.users_db)
            
            print(f"\n✅ Autenticación correcta")
            print(f"   - Usuario: {username}")
            print(f"   - Algoritmo: Argon2id verification")
            print(f"   - Timestamp: {self.users_db[username]['last_login']}")
            
            return True, "Autenticación correcta"
            
        except VerifyMismatchError:
            print(f"❌ Contraseña incorrecta para usuario '{username}'")
            return False, "Contraseña incorrecta"
        
        except (VerificationError, InvalidHash) as e:
            print(f"❌ Error en verificación: {e}")
            return False, "Error en la autenticación"
    
    def user_exists(self, username):
        """
        Verifica si un usuario existe en el sistema
        
        Args:
            username: Nombre de usuario a verificar
            
        Returns:
            bool: True si el usuario existe
        """
        # Recargar usuarios por si acaso
        self.users_db = load_json(self.users_file)
        return username in self.users_db
    
    def get_all_users(self):
        """
        Obtiene la lista de todos los usuarios registrados
        
        Returns:
            list: Lista de nombres de usuario
        """
        self.users_db = load_json(self.users_file)
        return list(self.users_db.keys())
    
    def get_user_info(self, username):
        """
        Obtiene información básica de un usuario (sin el hash)
        
        Args:
            username: Nombre de usuario
            
        Returns:
            dict: Información del usuario o None
        """
        self.users_db = load_json(self.users_file)
        
        if username not in self.users_db:
            return None
        
        info = self.users_db[username].copy()
        # No retornar el hash por seguridad
        info.pop('hash', None)
        return info