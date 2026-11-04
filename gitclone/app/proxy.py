from __future__ import annotations

import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime
from zoneinfo import ZoneInfo
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel
from . import db, ia
from .metricas import METRICAS
from .sessoes import CLEARANCE, SESSOES, Sessao

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("zerotrust.proxy")

SIMULACAO = os.getenv("ZT_SIMULATION", "0") == "1"
CONFIAR_XFF = os.getenv("ZT_TRUST_XFF", "0") == "1"          # so atras de proxy confiavel
EXPLICAR_AO_CLIENTE = SIMULACAO or os.getenv("ZT_EXPLAIN_TO_CLIENT", "0") == "1"
FUSO = ZoneInfo(os.getenv("ZT_TZ", "America/Fortaleza"))
# Redes consideradas internas. NAO se usa ipaddress.is_private: ele classifica como
# "privadas" as faixas de documentacao (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
_REDES_PADRAO = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fc00::/7,fe80::/10"
REDES_INTERNAS = [ipaddress.ip_network(n.strip()) for n in
                  (os.getenv("ZT_INTERNAL_NETS") or _REDES_PADRAO).split(",") if n.strip()]


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.iniciar()
    log.info("PEP iniciado (simulacao=%s)", SIMULACAO)
    yield
    db.encerrar()


app = FastAPI(title="Zero Trust PEP", version="2.0", lifespan=lifespan)


# Extracao de contexto

def obter_ip(request: Request) -> str:
    if SIMULACAO and request.headers.get("x-simulated-ip"):
        return request.headers["x-simulated-ip"].strip()
    if CONFIAR_XFF and request.headers.get("x-forwarded-for"):
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    return request.client.host if request.client else "desconhecido"


def ip_e_externo(ip: str) -> int:
    """1 se o IP esta fora das redes internas.
    NOTA: atras do NAT do Docker o IP visto pode ser o do gateway (172.x),
    que parece interno; em producao use ZT_TRUST_XFF=1 atras de proxy confiavel."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 1                                    # IP invalido => nao confiavel
    return int(not any(addr.version == rede.version and addr in rede for rede in REDES_INTERNAS))


def obter_hora(request: Request) -> int:
    if SIMULACAO:
        h = request.headers.get("x-simulated-hour", "")
        if h.isdigit() and 0 <= int(h) <= 23:
            return int(h)
    return datetime.now(FUSO).hour


def obter_rotulo(request: Request) -> str | None:
    if SIMULACAO:
        r = request.headers.get("x-scenario-label", "").lower()
        return r if r in ("legitimo", "malicioso") else None
    return None


def obter_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else None


def _ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000

# Decisao
def decidir(score: float) -> tuple[str, str]:
    d = ia.nivel_decisao(score)
    return d, {"NEGAR": "risco_elevado", "RESTRINGIR": "risco_moderado",
               "PERMITIR": "risco_baixo"}[d]


def _corpo_decisao(decisao, motivo, av: ia.Avaliacao | None, sessao: Sessao | None, eventos):
    corpo = {"decisao": decisao, "motivo": motivo, "eventos": eventos}
    if av is not None:
        corpo["score"] = round(av.score, 4)
        if EXPLICAR_AO_CLIENTE:
            corpo["explicacao"] = av.explicacao
            corpo["fatores"] = [f for f in av.to_dict()["fatores"]]
    if sessao is not None:
        corpo["nivel_confianca"] = round(sessao.confianca, 3)
        corpo["privilegio_atual"] = sessao.privilegio
    return corpo

# Endpoints
class LoginIn(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    return {"status": "ok", "simulacao": SIMULACAO}


@app.post("/login")
def login(dados: LoginIn, request: Request, response: Response):
    """Autenticacao inicial TAMBEM passa pelo PDP (credenciais corretas nao bastam)."""
    t0 = time.perf_counter()
    ip, ua, hora, rotulo = (obter_ip(request), request.headers.get("user-agent", ""),
                            obter_hora(request), obter_rotulo(request))
    usuario = db.obter_usuario(dados.username)
    role = usuario["role"] if usuario else "viewer"
    known = set(usuario["ips_conhecidos"]) if usuario else set()

    comp = SESSOES.contexto_login(ip)
    ctx = ia.Contexto(hora=hora, ip_externo=ip_e_externo(ip), ip_novo=int(ip not in known),
                      ip_mudou=0, ua_mudou=0, ua_automatizado=ia.ua_automatizado(ua),
                      sens_recurso=0, margem_privilegio=CLEARANCE.get(role, 1), **comp)
    t1 = time.perf_counter()
    av = ia.avaliar_risco(ctx)
    lat_dec = _ms(t1)
    decisao, motivo = decidir(av.score)

    credenciais_ok = db.verificar_senha(usuario, dados.password)
    SESSOES.registrar_login(ip, credenciais_ok)
    token, sessao, eventos, status = None, None, [], 200

    if not credenciais_ok:
        decisao, motivo, status = "NEGAR", "credenciais_invalidas", 401
        METRICAS.contar("credenciais_invalidas")
    elif decisao == "NEGAR":
        status = 403
    else:
        priv = None
        if decisao == "RESTRINGIR":
            priv = CLEARANCE[role] - 1
            eventos.append("PRIVILEGIO_REDUZIDO:no_login")
        token, sessao = SESSOES.criar(usuario["username"], role, ip, ua, known, priv)

    lat_tot = _ms(t0)
    if motivo != "credenciais_invalidas":          # so mede o modelo quando ele foi decisivo
        METRICAS.registrar(decisao, rotulo, eventos, lat_dec, lat_tot)
    db.registrar_auditoria(
        evento="login", username=dados.username, sessao=sessao.id_hash[:12] if sessao else None,
        ip=ip, user_agent=ua, recurso=None, hora=hora, score=av.score, decisao=decisao,
        motivo=motivo, fatores=av.to_dict()["fatores"], eventos=eventos,
        lat_decisao_ms=lat_dec, lat_total_ms=lat_tot, rotulo=rotulo)

    response.status_code = status
    response.headers["X-Decision-Time-Ms"] = f"{lat_dec:.3f}"
    corpo = _corpo_decisao(decisao, motivo, av, sessao, eventos)
    if token:
        corpo.update(session_token=token, role=role)
    return corpo


def sessao_atual(request: Request) -> Sessao:
    token = obter_token(request)
    if not token:
        raise HTTPException(401, "Credencial ausente (Authorization: Bearer <token>)")
    s = SESSOES.obter(token)
    if s is None:
        raise HTTPException(401, "Sessao invalida")
    return s


@app.get("/recurso/{nome}")
def acessar_recurso(nome: str, request: Request, response: Response,
                    sessao: Sessao = Depends(sessao_atual)):
    """Ponto central: avaliacao continua de risco a cada acesso."""
    t0 = time.perf_counter()
    ip, ua, hora, rotulo = (obter_ip(request), request.headers.get("user-agent", ""),
                            obter_hora(request), obter_rotulo(request))
    recurso = db.obter_recurso(nome)
    if recurso is None:
        raise HTTPException(404, "Recurso inexistente")
    sens = recurso["sensibilidade"]

    # --- sessao ja revogada: nenhuma nova avaliacao, exige reautenticacao
    if sessao.revogada:
        lat = _ms(t0)
        METRICAS.registrar("NEGAR", rotulo, [], 0.0, lat, motivo="sessao_revogada")
        db.registrar_auditoria(
            evento="acesso", username=sessao.username, sessao=sessao.id_hash[:12], ip=ip,
            user_agent=ua, recurso=nome, hora=hora, score=None, decisao="NEGAR",
            motivo="sessao_revogada", fatores=None, eventos=[], lat_decisao_ms=0.0,
            lat_total_ms=lat, rotulo=rotulo)
        raise HTTPException(401, "Sessao revogada por risco: reautenticacao necessaria")

    # --- contexto + PDP
    comp = SESSOES.registrar_requisicao(sessao, nome)
    ctx = ia.Contexto(
        hora=hora, ip_externo=ip_e_externo(ip), ip_novo=int(ip not in sessao.ips_conhecidos),
        ip_mudou=int(ip != sessao.ip_inicial), ua_mudou=int(ua != sessao.ua_inicial),
        ua_automatizado=ia.ua_automatizado(ua), sens_recurso=sens,
        margem_privilegio=sessao.privilegio - sens, **comp)
    t1 = time.perf_counter()
    av = ia.avaliar_risco(ctx)
    lat_dec = _ms(t1)

    # --- politica: regra deterministica (defesa em profundidade) + risco
    decisao, motivo = decidir(av.score)
    if sens > sessao.privilegio and decisao != "NEGAR":
        decisao, motivo = "NEGAR", "privilegio_insuficiente"

    # --- reavaliacao da confianca da sessao
    eventos = SESSOES.aplicar_decisao(sessao, decisao, av.score)

    bloqueado = decisao == "NEGAR"
    if decisao == "RESTRINGIR" and sens > sessao.privilegio:     
        bloqueado, motivo = True, "acima_do_privilegio_reduzido"

    dados = None if bloqueado else db.ler_dados(recurso)         
    lat_tot = _ms(t0)

    METRICAS.registrar(decisao, rotulo, eventos, lat_dec, lat_tot)
    db.registrar_auditoria(
        evento="acesso", username=sessao.username, sessao=sessao.id_hash[:12], ip=ip,
        user_agent=ua, recurso=nome, hora=hora, score=av.score, decisao=decisao, motivo=motivo,
        fatores=av.to_dict()["fatores"], eventos=eventos, lat_decisao_ms=lat_dec,
        lat_total_ms=lat_tot, rotulo=rotulo)

    response.headers["X-Decision-Time-Ms"] = f"{lat_dec:.3f}"
    corpo = _corpo_decisao(decisao, motivo, av, sessao, eventos)
    if bloqueado:
        response.status_code = 403
        return corpo
    corpo.update(status="Acesso autorizado", recurso=nome, dados=dados)
    return corpo


@app.post("/logout")
def logout(sessao: Sessao = Depends(sessao_atual)):
    SESSOES.encerrar(sessao)
    return {"status": "sessao encerrada"}


@app.get("/sessao")
def introspeccao(sessao: Sessao = Depends(sessao_atual)):
    return {"usuario": sessao.username, "role": sessao.role,
            "privilegio_atual": sessao.privilegio, "privilegio_maximo": sessao.clearance,
            "nivel_confianca": round(sessao.confianca, 3), "revogada": sessao.revogada}


# --- administracao / observabilidade
def admin(request: Request) -> None:
    """Em simulacao e livre (para os scripts); caso contrario exige sessao admin."""
    if SIMULACAO:
        return
    s = sessao_atual(request)
    if s.role != "admin" or s.revogada:
        raise HTTPException(403, "Apenas administradores")


@app.get("/metricas", dependencies=[Depends(admin)])
def metricas():
    return METRICAS.resumo()


@app.get("/auditoria", dependencies=[Depends(admin)])
def auditoria(limite: int = 50):
    return db.listar_auditoria(limite)


@app.get("/modelo", dependencies=[Depends(admin)])
def modelo():
    """Explicabilidade GLOBAL: coeficientes e metricas de teste do modelo."""
    return ia.INFO_MODELO


@app.post("/simulacao/reset")
def resetar(request: Request):
    if not SIMULACAO:
        raise HTTPException(404)
    METRICAS.resetar()
    SESSOES.limpar()
    db.limpar_auditoria()
    return {"status": "metricas, sessoes e auditoria zeradas"}