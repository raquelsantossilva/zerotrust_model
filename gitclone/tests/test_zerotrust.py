"""
Testes do prototipo Zero Trust.  Execucao:  pytest -v
Os testes de API exigem PostgreSQL acessivel (variaveis POSTGRES_*); sem banco, sao ignorados.
"""
import math
import os

import pytest

os.environ.setdefault("ZT_SIMULATION", "1")

from app import ia                                   # noqa: E402
from app.sessoes import GerenciadorSessoes           # noqa: E402

NAV = "Mozilla/5.0 Chrome/126.0"
BASE = dict(hora=10, ip_externo=0, ip_novo=0, ip_mudou=0, ua_mudou=0, ua_automatizado=0,
            sens_recurso=1, margem_privilegio=1, req_por_min=2, recursos_distintos=1,
            falhas_recentes=0)


def ctx(**kw):
    return {**BASE, **kw}


# ------------------------------------------------------------------ modelo
def test_acesso_legitimo_tem_risco_baixo():
    assert ia.avaliar_risco(ctx()).score < ia.LIMIAR_RESTRINGIR


def test_acesso_malicioso_e_negado():
    av = ia.avaliar_risco(ctx(hora=3, ip_externo=1, ip_novo=1, ua_automatizado=1,
                              req_por_min=25, recursos_distintos=3, falhas_recentes=2))
    assert av.score >= ia.LIMIAR_NEGAR


def test_horario_agora_influencia_a_decisao():
    """No prototipo anterior o coeficiente da hora era ~0 (atributo decorativo)."""
    dia = ia.avaliar_risco(ctx(hora=10, req_por_min=8)).score
    madrugada = ia.avaliar_risco(ctx(hora=3, req_por_min=8)).score
    assert madrugada > dia


def test_roubo_de_sessao_eleva_risco():
    normal = ia.avaliar_risco(ctx()).score
    roubo = ia.avaliar_risco(ctx(ip_mudou=1, ua_mudou=1, ip_externo=1, ip_novo=1)).score
    assert roubo > normal + 0.3


def test_explicacao_soma_exatamente_o_logit():
    av = ia.avaliar_risco(ctx(hora=2, ip_externo=1, ua_automatizado=1))
    logit = math.log(av.score / (1 - av.score))
    soma = sum(f.contribuicao for f in av.fatores) + float(ia.MODELO.intercept_[0])
    assert soma == pytest.approx(logit, abs=1e-6)


def test_fator_principal_e_o_correto():
    av = ia.avaliar_risco(ctx(ua_automatizado=1, ip_externo=1, ip_novo=1, ip_mudou=1))
    topo = {f.nome for f in av.fatores[:3]}
    assert "Origem de rede (IP)" in topo or "Tipo de cliente" in topo


def test_modelo_supera_baseline_de_regra_fixa_em_recall():
    assert ia.INFO_MODELO["teste_limiar_negar"]["recall"] > \
        ia.INFO_MODELO["baseline_regra_fixa"]["recall"]


def test_ua_automatizado():
    assert ia.ua_automatizado("curl/8.5.0") == 1
    assert ia.ua_automatizado("python-requests/2.31") == 1
    assert ia.ua_automatizado("") == 1
    assert ia.ua_automatizado(NAV) == 0


# ------------------------------------------------------------------ sessoes
def test_privilegio_reduz_restaura_e_sessao_revoga():
    g = GerenciadorSessoes()
    _, s = g.criar("u", "analista", "10.0.0.1", NAV)
    assert s.privilegio == 2
    ev = g.aplicar_decisao(s, "RESTRINGIR", 0.5)
    assert s.privilegio == 1 and ev[0].startswith("PRIVILEGIO_REDUZIDO")
    restaurou = []
    for _ in range(5):
        restaurou += g.aplicar_decisao(s, "PERMITIR", 0.01)
    assert s.privilegio == 2 and any(e.startswith("PRIVILEGIO_RESTAURADO") for e in restaurou)
    for _ in range(6):
        g.aplicar_decisao(s, "NEGAR", 0.99)
    assert s.revogada


def test_janela_de_taxa():
    g = GerenciadorSessoes()
    _, s = g.criar("u", "viewer", "10.0.0.1", NAV)
    for i in range(5):
        c = g.registrar_requisicao(s, "redes" if i % 2 else "publico")
    assert c["req_por_min"] == 5 and c["recursos_distintos"] == 2


# ---------------------------------------------------------------------- API
@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from app import db
    from app.proxy import app
    try:
        with TestClient(app) as c:
            c.post("/simulacao/reset")
            yield c
    except RuntimeError:
        pytest.skip("PostgreSQL indisponivel")


def H(ip="10.0.0.11", hora=10, ua=NAV, token=None, rotulo="legitimo"):
    h = {"X-Simulated-IP": ip, "X-Simulated-Hour": str(hora), "User-Agent": ua,
         "X-Scenario-Label": rotulo}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def login(c, user="ana", senha="demo123", **kw):
    r = c.post("/login", json={"username": user, "password": senha}, headers=H(**kw))
    return r, r.json().get("session_token")


def test_sem_token_retorna_401(client):
    assert client.get("/recurso/redes").status_code == 401


def test_varias_requisicoes_seguidas_funcionam(client):
    """Regressao: a versao antiga fechava a conexao global e a 2a requisicao falhava."""
    _, tok = login(client, ip="10.0.0.12", user="bruno")
    for _ in range(3):
        r = client.get("/recurso/redes", headers=H(ip="10.0.0.12", token=tok))
        assert r.status_code == 200 and r.json()["dados"][0]["professor"] == "pitagoras"


def test_senha_errada_e_401(client):
    r, tok = login(client, senha="errada")
    assert r.status_code == 401 and tok is None


def test_roubo_de_sessao_e_bloqueado(client):
    _, tok = login(client, user="carla", ip="10.0.0.13")
    r = client.get("/recurso/admin_config",
                   headers=H(ip="203.0.113.9", hora=3, token=tok, rotulo="malicioso",
                             ua="Mozilla/5.0 Firefox/115.0"))
    assert r.status_code == 403 and r.json()["decisao"] == "NEGAR"


def test_escalada_de_privilegio_negada_antes_do_banco(client):
    _, tok = login(client, user="eva", ip="10.0.0.15")
    r = client.get("/recurso/financeiro", headers=H(ip="10.0.0.15", token=tok))
    assert r.status_code == 403 and "dados" not in r.json()


def test_reavaliacao_revoga_sessao_sequestrada(client):
    _, tok = login(client, user="bruno", ip="10.0.0.12")
    cods = [client.get("/recurso/financeiro",
                       headers=H(ip="198.51.100.5", hora=2, ua="curl/8.5.0", token=tok,
                                 rotulo="malicioso")).status_code for _ in range(6)]
    assert set(cods) == {403, 401}                      # negadas e, depois, sessao revogada
    assert client.get("/sessao", headers=H(token=tok)).json()["revogada"] is True


def test_metricas_e_auditoria_populadas(client):
    m = client.get("/metricas").json()
    assert m["totais"]["total"] > 0 and m["latencia_decisao_modelo"]["n"] > 0
    assert m["avaliacao_rotulada"]["acessos_indevidos_bloqueados"] > 0
    aud = client.get("/auditoria?limite=5").json()
    assert aud and "decisao" in aud[0]


def test_cabecalhos_de_simulacao_sao_ignorados_fora_do_modo_simulacao(client, monkeypatch):
    from app import proxy
    monkeypatch.setattr(proxy, "SIMULACAO", False)
    # o IP simulado (interno) NAO deve ser aceito; testclient nao e IP valido => externo
    assert proxy.ip_e_externo("203.0.113.5") == 1
    from starlette.requests import Request
    req = Request({"type": "http", "headers": [(b"x-simulated-ip", b"10.0.0.1")],
                   "client": ("203.0.113.5", 1234)})
    assert proxy.obter_ip(req) == "203.0.113.5"
