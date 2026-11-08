"""Lambda Authorizer (HTTP API, payload 2.0, respuestas simples).

Lo usan los 5 MS. Valida el token contra la tabla de tokens y entrega a la ruta
{tenant_id, usuario_id, rol, plan} en requestContext.authorizer.lambda.
API Gateway cachea el resultado 5 minutos por token.
"""
import os
import time

import boto3

tokens = boto3.resource('dynamodb').Table(os.environ['TABLA_TOKENS'])


def main(event, _context):
    cabecera = (event.get('headers') or {}).get('authorization', '')
    token = cabecera[7:].strip() if cabecera.lower().startswith('bearer ') else cabecera.strip()
    if not token:
        return {'isAuthorized': False}

    item = tokens.get_item(Key={'token': token}).get('Item')
    # El TTL de DynamoDB borra con retraso, así que se compara la expiración aquí también.
    if not item or int(item['expira']) < time.time():
        return {'isAuthorized': False}

    return {
        'isAuthorized': True,
        'context': {
            'tenant_id': item['tenant_id'],
            'usuario_id': item['usuario_id'],
            'rol': item['rol'],
            'plan': item['plan'],
        },
    }
