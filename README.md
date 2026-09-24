🔒 Sistema de Mensajería Segura (PKI & Cifrado Híbrido)
Este proyecto implementa una plataforma de mensajería segura desarrollada en Python. Combina autenticación robusta de usuarios, una Infraestructura de Clave Pública (PKI) jerárquica, cifrado híbrido para garantizar la confidencialidad y firmas digitales para asegurar la integridad y el no repudio de los mensajes.
---
👥 Colaboradores
María Arias
---
🚀 Características Principales
Autenticación Segura: Hash de contraseñas mediante el algoritmo Argon2 con salado y validación estricta de credenciales.
Infraestructura de Clave Pública (PKI):
Generación de una Autoridad Certificadora Raíz (CA Raíz) autofirmada.
Gestión de Autoridades Certificadoras Subordinadas.
Emisión, almacenamiento y validación de la cadena completa de certificados X.509 para los usuarios.
Cifrado Híbrido de Mensajes: Combinación de criptografía asimétrica (RSA) y simétrica para garantizar que solo el destinatario legítimo pueda leer el contenido.
Firma Digital e Integridad: Firmado digital de mensajes para verificar la identidad del emisor y descartar manipulaciones.
Suite de Pruebas: Pruebas unitarias integradas (`tests.py`) que verifican la integridad de las cadenas de certificados, firmas digitales y gestión de claves.
---
🛠️ Requisitos e Instalación
Prerrequisitos
El proyecto requiere Python 3.8+ y las bibliotecas criptográficas especificadas.
Instalación de dependencias
Instala los paquetes necesarios ejecutando:
```bash
pip install cryptography argon2-cffi
```
---
📂 Estructura del Proyecto
```text
.
├── autenticacion.py                # Gestión de registros, login y hashing con Argon2
├── certificado.py                  # Utilidades para carga y lectura de certificados X.509
├── crear_usuarios.py               # Creación de estructura de directorios y gestión de claves por usuario
├── encriptado_hibrido.py           # Funciones de cifrado y descifrado de mensajes
├── firmas.py                       # Firma digital y verificación criptográfica
├── gestor_certificados_usuarios.py # Emisión y consulta de certificados de usuarios
├── inicializar_pki.py              # Creación e inicialización de la CA Raíz y CAs Subordinadas
├── verificador_cadenas.py          # Validación de la cadena de confianza de los certificados
├── main.py                         # Interfaz de consola e interactividad del sistema
└── tests.py                        # Pruebas unitarias del sistema
```
---
💻 Uso
1. Ejecutar el sistema
Para iniciar el menú interactivo del sistema de mensajería:
```bash
python main.py
```
Al ejecutarlo por primera vez, el sistema inicializará automáticamente la jerarquía de la PKI si no existe.
2. Ejecutar la suite de pruebas
Para comprobar el correcto funcionamiento de las funciones criptográficas y la validación de certificados:
```bash
python -m unittest tests.py
```

Reame hecho por Gemini
