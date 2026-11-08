# MS1 · Tenants y Usuarios — CRM SaaS (CS2032 · Grupo 1)

Registro de empresas (tenants), login, usuarios, roles y el **Lambda Authorizer** que protege a los 5 microservicios.
Base de datos: **DynamoDB**. Orquestación y arquitectura: [crm-grupo1-infra](https://github.com/enriquetorres-cell/crm-grupo1-infra).

## Endpoints (`/ms1`)

| Método | Ruta | Acceso |
| --- | --- | --- |
| GET | `/ms1/health` | público |
| POST | `/ms1/tenants` | público (alta self-service + primer admin) |
| POST | `/ms1/login` | público → `{token, expira_en, usuario, plan}` |
| GET | `/ms1/me` | token |
| GET | `/ms1/usuarios` | admin, gerente |
| POST | `/ms1/usuarios` | admin (respeta el límite del plan: básico 5, pro 20, enterprise ∞) |
| POST | `/ms1/usuarios/{email}/suspender` | admin |

## Eventos

- **Publica:** `tenant.creado` (MS2 y MS4 crean el schema), `usuario.creado` (MS3, MS5).
- **Consume:** —

## Estructura DynamoDB

| Tabla | Clave | Ejemplo |
| --- | --- | --- |
| `crm-ms1-<stage>-tenants` | `tenant_id` | `{"tenant_id":"tenant_andina","nombre":"Andina Seguros","plan":"pro","activo":true,"creado_en":"2026-11-08T15:00:00Z"}` |
| `crm-ms1-<stage>-usuarios` | `tenant_id` + `email` | `{"tenant_id":"tenant_andina","email":"ana@andina.pe","nombre":"Ana","rol":"vendedor","password_hash":"<sal>$<pbkdf2>","activo":true}` |
| `crm-ms1-<stage>-tokens` | `token` (TTL `expira`) | `{"token":"…","tenant_id":"tenant_andina","usuario_id":"ana@andina.pe","rol":"vendedor","plan":"pro","expira":1762621200}` |

## Desplegar

Requiere que `crm-compartido` (repo infra) ya esté desplegado. **Se despliega antes que MS2–MS5**, porque ellos usan su Authorizer.

```bash
npm install
npx serverless deploy --stage dev
```

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

`src/comun.py` es una copia de `comun/comun.py` del repo infra: no lo edites aquí, sino allá, y corre `sincronizar-comun`.
