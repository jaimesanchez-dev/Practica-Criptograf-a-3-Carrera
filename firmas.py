from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

def firma_mensaje(clave_privada, mensaje):
    """Firmamos con la clave privada los datos del mensaje"""
    firma = clave_privada.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
    )
    return firma

def verificar_firma(certificado, mensaje, firma):
    """Devuelve un true un o false"""
    