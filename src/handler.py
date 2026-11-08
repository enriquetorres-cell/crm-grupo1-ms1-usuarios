"""MS1 · Tenants y Usuarios: registro de empresa, login, usuarios y roles.

Publica: tenant.creado (MS2 y MS4 crean el schema del tenant), usuario.creado.
"""
import hashlib
import hmac
import os
import secrets
import time

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from . import reglas
from .comun import (NoEncontrado, ReglaNoCumplida, consultar_pagina, enrutar, exigir_rol, iso,
                    ahora, leer_cuerpo, publicar, responder)

_dynamo = boto3.resource('dynamodb')
tenants = _dynamo.Table(os.environ['TABLA_TENANTS'])
usuarios = _dynamo.Table(os.environ['TABLA_USUARIOS'])
tokens = _dynamo.Table(os.environ['TABLA_TOKENS'])


def _hash(password, sal=None):
    sal = sal or secrets.token_hex(16)
    clave = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(sal), 100_000).hex()
    return f'{sal}${clave}'


def _password_correcto(password, guardado):
    sal = guardado.split('$', 1)[0]
    return hmac.compare_digest(_hash(password, sal), guardado)


def _publico(usuario):
    return {k: v for k, v in usuario.items() if k != 'password_hash'}


def _es_condicion_fallida(error):
    return error.response['Error']['Code'] == 'ConditionalCheckFailedException'


def _crear_usuario(tenant_id, datos, rol):
    usuario = {
        'tenant_id': tenant_id,
        'email': reglas.validar_email(datos.get('email')),
        'nombre': reglas.texto_obligatorio(datos.get('nombre'), 'nombre'),
        'rol': reglas.validar_rol(rol),
        'password_hash': _hash(reglas.validar_password(datos.get('password'))),
        'activo': True,
        'creado_en': iso(ahora()),
    }
    try:
        usuarios.put_item(Item=usuario, ConditionExpression='attribute_not_exists(email)')
    except ClientError as e:
        if _es_condicion_fallida(e):
            raise ReglaNoCumplida('email_existente', 'Ese email ya está registrado en esta empresa')
        raise
    publicar('usuario.creado', tenant_id, {k: usuario[k] for k in ('email', 'nombre', 'rol')})
    return _publico(usuario)


# ---------- Rutas ----------

def salud(event, ctx):
    return responder(200, {'status': 'ok', 'servicio': 'ms1'})


def registrar_tenant(event, ctx):
    """Alta self-service de una empresa con su primer usuario admin (ruta pública)."""
    datos = leer_cuerpo(event)
    tenant = {
        'tenant_id': reglas.validar_tenant_id(datos.get('tenant_id')),
        'nombre': reglas.texto_obligatorio(datos.get('nombre'), 'nombre'),
        'plan': reglas.validar_plan(datos.get('plan', 'basico')),
        'activo': True,
        'creado_en': iso(ahora()),
    }
    admin = datos.get('admin') or {}
    # Se valida el admin ANTES de crear el tenant para no dejar empresas sin usuario.
    reglas.validar_email(admin.get('email'))
    reglas.validar_password(admin.get('password'))
    reglas.texto_obligatorio(admin.get('nombre'), 'admin.nombre')
    try:
        tenants.put_item(Item=tenant, ConditionExpression='attribute_not_exists(tenant_id)')
    except ClientError as e:
        if _es_condicion_fallida(e):
            raise ReglaNoCumplida('tenant_existente', f'{tenant["tenant_id"]} ya está registrado')
        raise
    publicar('tenant.creado', tenant['tenant_id'], {'nombre': tenant['nombre'], 'plan': tenant['plan']})
    usuario = _crear_usuario(tenant['tenant_id'], admin, 'admin')
    return responder(201, {'tenant': tenant, 'usuario': usuario})


def login(event, ctx):
    datos = leer_cuerpo(event)
    tenant_id = reglas.validar_tenant_id(datos.get('tenant_id'))
    email = reglas.validar_email(datos.get('email'))
    usuario = usuarios.get_item(Key={'tenant_id': tenant_id, 'email': email}).get('Item')
    tenant = tenants.get_item(Key={'tenant_id': tenant_id}).get('Item')
    # Mismo error para "no existe" y "clave incorrecta": no se revela qué emails existen.
    if not usuario or not _password_correcto(str(datos.get('password', '')), usuario['password_hash']):
        return responder(401, {'error': 'credenciales_invalidas', 'detalle': None})
    if not reglas.puede_iniciar_sesion(usuario, tenant):
        return responder(403, {'error': 'cuenta_suspendida', 'detalle': 'El usuario o la empresa están suspendidos'})

    token = secrets.token_urlsafe(32)
    expira = int(time.time()) + reglas.HORAS_SESION * 3600
    tokens.put_item(Item={
        'token': token, 'tenant_id': tenant_id, 'usuario_id': email,
        'rol': usuario['rol'], 'plan': tenant['plan'], 'expira': expira,
    })
    return responder(200, {
        'token': token,
        'expira_en': expira,
        'tenant_id': tenant_id,
        'tenant_nombre': tenant['nombre'],
        'usuario': _publico(usuario),
        'plan': tenant['plan'],
    })


def yo(event, ctx):
    return responder(200, ctx)


def listar_usuarios(event, ctx):
    exigir_rol(ctx, 'admin', 'gerente')
    pagina = consultar_pagina(usuarios, event, KeyConditionExpression=Key('tenant_id').eq(ctx['tenant_id']))
    pagina['items'] = [_publico(u) for u in pagina['items']]
    return responder(200, pagina)


def crear_usuario(event, ctx):
    exigir_rol(ctx, 'admin')
    datos = leer_cuerpo(event)
    actuales = _contar_usuarios(ctx['tenant_id'])
    if not reglas.puede_agregar_usuario(ctx['plan'], actuales):
        limite = reglas.PLANES[ctx['plan']]['usuarios']
        raise ReglaNoCumplida('limite_plan', f'El plan {ctx["plan"]} permite {limite} usuarios')
    return responder(201, _crear_usuario(ctx['tenant_id'], datos, datos.get('rol', 'vendedor')))


def suspender_usuario(event, ctx):
    exigir_rol(ctx, 'admin')
    email = reglas.validar_email((event.get('pathParameters') or {}).get('email'))
    if email == ctx['usuario_id']:
        raise ReglaNoCumplida('autosuspension', 'Un admin no puede suspenderse a sí mismo')
    try:
        usuarios.update_item(
            Key={'tenant_id': ctx['tenant_id'], 'email': email},
            UpdateExpression='SET activo = :no',
            ConditionExpression='attribute_exists(email)',
            ExpressionAttributeValues={':no': False},
        )
    except ClientError as e:
        if _es_condicion_fallida(e):
            raise NoEncontrado('usuario_no_encontrado', email)
        raise
    # Sus tokens vigentes siguen valiendo hasta 5 min por la caché del Authorizer.
    return responder(200, {'email': email, 'activo': False})


def _contar_usuarios(tenant_id):
    total, inicio = 0, None
    while True:
        kwargs = {'KeyConditionExpression': Key('tenant_id').eq(tenant_id), 'Select': 'COUNT'}
        if inicio:
            kwargs['ExclusiveStartKey'] = inicio
        respuesta = usuarios.query(**kwargs)
        total += respuesta['Count']
        inicio = respuesta.get('LastEvaluatedKey')
        if not inicio:
            return total


RUTAS = {
    'GET /ms1/health': salud,
    'POST /ms1/tenants': registrar_tenant,
    'POST /ms1/login': login,
    'GET /ms1/me': yo,
    'GET /ms1/usuarios': listar_usuarios,
    'POST /ms1/usuarios': crear_usuario,
    'POST /ms1/usuarios/{email}/suspender': suspender_usuario,
}


def main(event, _context):
    return enrutar(RUTAS, event)
