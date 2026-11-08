import pytest

from src import reglas
from src.comun import DatoInvalido


@pytest.mark.parametrize('plan, actuales, esperado', [
    ('basico', 4, True),
    ('basico', 5, False),
    ('pro', 19, True),
    ('pro', 20, False),
    ('enterprise', 10_000, True),
])
def test_limite_de_usuarios_por_plan(plan, actuales, esperado):
    assert reglas.puede_agregar_usuario(plan, actuales) is esperado


def test_tenant_id_valido_es_nombre_de_schema():
    assert reglas.validar_tenant_id('tenant_andina') == 'tenant_andina'


@pytest.mark.parametrize('malo', ['andina', 'tenant_A', 'tenant_ab', 'tenant_x; DROP TABLE', None])
def test_tenant_id_invalido(malo):
    with pytest.raises(DatoInvalido):
        reglas.validar_tenant_id(malo)


def test_email_se_normaliza():
    assert reglas.validar_email('  Ana@Andina.PE ') == 'ana@andina.pe'


def test_password_debe_tener_letras_y_numeros():
    with pytest.raises(DatoInvalido):
        reglas.validar_password('solotexto')
    assert reglas.validar_password('clave2026')


def test_usuario_o_tenant_suspendido_no_inicia_sesion():
    assert reglas.puede_iniciar_sesion({'activo': True}, {'activo': True})
    assert not reglas.puede_iniciar_sesion({'activo': False}, {'activo': True})
    assert not reglas.puede_iniciar_sesion({'activo': True}, {'activo': False})
    assert not reglas.puede_iniciar_sesion(None, {'activo': True})
