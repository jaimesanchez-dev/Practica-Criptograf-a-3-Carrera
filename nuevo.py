from certificado import *

a = AutoridadCertificacion("raiz", True, None)
b = AutoridadCertificacion("A", False, a)
c = AutoridadCertificacion("B", False, a)