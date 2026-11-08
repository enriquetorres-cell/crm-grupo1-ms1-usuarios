"""Reglas de negocio de MS1 (Tenants y Usuarios). Sin BD ni HTTP: se prueban solas."""
import re

from .comun import DatoInvalido

# Límites por plan. None = sin límite. MS3 tiene la misma tabla para leads_mes.
PLANES = {
    'basico': {'usuarios': 5, 'leads_mes': 1000},
    'pro': {'usuarios': 20, 'leads_mes': 10000},
    'enterprise': {'usuarios': None, 'leads_mes': None},
}
ROLES = ('admin', 'gerente', 'vendedor')
HORAS_SESION = 8

_PATRON_TENANT = re.compile(r'tenant_[a-z0-9]{3,30}')
_PATRON_EMAIL = re.compile(r'[^@\s]+@[^@\s]+\.[a-z]{2,}', re.IGNORECASE)


def validar_tenant_id(valor):
    """El tenant_id también es el nombre del schema en el RDS: solo minúsculas y dígitos."""
    if not isinstance(valor, str) or not _PATRON_TENANT.fullmatch(valor):
        raise DatoInvalido('tenant_id_invalido', 'Formato: tenant_<3 a 30 minúsculas o dígitos>, p. ej. tenant_andina')
    return valor


def validar_plan(valor):
    if valor not in PLANES:
        raise DatoInvalido('plan_invalido', f'Planes: {", ".join(PLANES)}')
    return valor


def validar_rol(valor):
    if valor not in ROLES:
        raise DatoInvalido('rol_invalido', f'Roles: {", ".join(ROLES)}')
    return valor


def validar_email(valor):
    if not isinstance(valor, str) or not _PATRON_EMAIL.fullmatch(valor.strip()):
        raise DatoInvalido('email_invalido', 'Email con formato nombre@dominio.com')
    return valor.strip().lower()


def validar_password(valor):
    if not isinstance(valor, str) or len(valor) < 8:
        raise DatoInvalido('password_invalido', 'Mínimo 8 caracteres')
    if not (re.search(r'[A-Za-z]', valor) and re.search(r'\d', valor)):
        raise DatoInvalido('password_invalido', 'Debe tener letras y números')
    return valor


def texto_obligatorio(valor, campo, maximo=120):
    if not isinstance(valor, str) or not valor.strip():
        raise DatoInvalido('campo_obligatorio', f'{campo} es obligatorio')
    if len(valor.strip()) > maximo:
        raise DatoInvalido('campo_muy_largo', f'{campo} admite máximo {maximo} caracteres')
    return valor.strip()


def puede_agregar_usuario(plan, usuarios_actuales):
    """Regla del plan: básico 5, pro 20, enterprise sin límite."""
    limite = PLANES[plan]['usuarios']
    return limite is None or usuarios_actuales < limite


def puede_iniciar_sesion(usuario, tenant):
    """Un usuario suspendido, o de un tenant suspendido, no obtiene token."""
    return bool(usuario and tenant and usuario.get('activo', True) and tenant.get('activo', True))
