from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import Json, RealDictCursor
from psycopg2.pool import ThreadedConnectionPool

log = logging.getLogger("zerotrust.db")

DB_CFG = dict(
    host=os.getenv("POSTGRES_HOST", "db"),
    port=int(os.getenv("POSTGRES_PORT", "5432")),
    dbname=os.getenv("POSTGRES_DB", "ufc_data"),
    user=os.getenv("POSTGRES_USER", "postgres"),
    password=os.getenv("POSTGRES_PASSWORD", ""),
)
SENHA_DEMO = os.getenv("ZT_DEMO_PASSWORD", "demo123")    # apenas para a demonstracao
_pool: ThreadedConnectionPool | None = None

# usuario, role, IPs historicamente associados ao usuario
USUARIOS_DEMO = [
    ("ana", "viewer", ["10.0.0.11", "127.0.0.1"]),
    ("bruno", "analista", ["10.0.0.12", "127.0.0.1"]),
    ("carla", "admin", ["10.0.0.13", "127.0.0.1"]),
    ("diego", "analista", ["10.0.0.14", "127.0.0.1"]),
    ("eva", "viewer", ["10.0.0.15", "127.0.0.1"]),
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS redes(
    id SERIAL PRIMARY KEY,
    professor VARCHAR(50) NOT NULL UNIQUE,
    numero_alunos INT
);
CREATE TABLE IF NOT EXISTS usuarios(
    username TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    senha_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    ips_conhecidos TEXT[] NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS recursos(
    nome TEXT PRIMARY KEY,
    sensibilidade INT NOT NULL CHECK (sensibilidade BETWEEN 0 AND 3),
    conteudo JSONB
);
CREATE TABLE IF NOT EXISTS auditoria(
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    evento TEXT NOT NULL,            -- acesso | login
    username TEXT,
    sessao TEXT,                     -- apenas prefixo do hash do token
    ip TEXT, user_agent TEXT, recurso TEXT, hora INT,
    score REAL, decisao TEXT, motivo TEXT,
    fatores JSONB, eventos TEXT[],
    lat_decisao_ms REAL, lat_total_ms REAL, rotulo TEXT
);
CREATE INDEX IF NOT EXISTS idx_auditoria_ts ON auditoria(ts DESC);
"""


def _hash(senha: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(salt), 120_000).hex()


def iniciar(tentativas: int = 30) -> None:
    #Abre o pool (aguardando o banco subir) e garante esquema + dados de demo.
    global _pool
    for i in range(tentativas):
        try:
            _pool = ThreadedConnectionPool(1, 10, cursor_factory=RealDictCursor, **DB_CFG)
            break
        except psycopg2.OperationalError as e:
            log.warning("Banco indisponivel (%s/%s): %s", i + 1, tentativas, str(e).strip())
            time.sleep(1)
    else:
        raise RuntimeError("Nao foi possivel conectar ao PostgreSQL")

    with cursor() as cur:
        cur.execute(SCHEMA)
        cur.execute("INSERT INTO redes(professor, numero_alunos) VALUES ('pitagoras', 30) "
                    "ON CONFLICT (professor) DO NOTHING")
        for nome, sens, conteudo in [
            ("publico", 0, {"aviso": "Informacao aberta a qualquer usuario autenticado"}),
            ("redes", 1, None),                                     # le a tabela `redes`
            ("financeiro", 2, {"orcamento_lab": 120000, "centro_custo": "REDES-01"}),
            ("admin_config", 3, {"chave_api_interna": "***", "politica": "zero-trust-v1"}),
        ]:
            cur.execute("INSERT INTO recursos(nome, sensibilidade, conteudo) VALUES (%s,%s,%s) "
                        "ON CONFLICT (nome) DO NOTHING", (nome, sens, Json(conteudo)))
        for user, role, ips in USUARIOS_DEMO:
            salt = secrets.token_hex(16)
            cur.execute("INSERT INTO usuarios(username, role, senha_hash, salt, ips_conhecidos) "
                        "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (username) DO NOTHING",
                        (user, role, _hash(SENHA_DEMO, salt), salt, ips))


def encerrar() -> None:
    if _pool:
        _pool.closeall()


@contextmanager
def cursor():
    #Entrega um cursor de uma conexao do pool; commit/rollback automaticos.
    conn = _pool.getconn()
    try:
        with conn.cursor() as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _pool.putconn(conn)


# consultas
def obter_usuario(username: str) -> dict | None:
    with cursor() as cur:
        cur.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
        return cur.fetchone()


def verificar_senha(usuario: dict | None, senha: str) -> bool:
    #Tempo ~constante mesmo quando o usuario nao existe (evita enumeracao).
    salt = usuario["salt"] if usuario else "00" * 16
    calc = _hash(senha, salt)
    return bool(usuario) and hmac.compare_digest(calc, usuario["senha_hash"])


def obter_recurso(nome: str) -> dict | None:
    with cursor() as cur:
        cur.execute("SELECT nome, sensibilidade, conteudo FROM recursos WHERE nome = %s", (nome,))
        return cur.fetchone()


def ler_dados(recurso: dict):
    #Le o conteudo do recurso (o recurso 'redes' vem da tabela original).
    if recurso["nome"] == "redes":
        with cursor() as cur:
            cur.execute("SELECT id, professor, numero_alunos FROM redes ORDER BY id")
            return cur.fetchall()
    return recurso["conteudo"]


def registrar_auditoria(**kw) -> None:
    #Melhor esforco: falha de auditoria nao derruba a requisicao, mas e logada.
    try:
        with cursor() as cur:
            cur.execute(
                """INSERT INTO auditoria(evento, username, sessao, ip, user_agent, recurso, hora,
                       score, decisao, motivo, fatores, eventos, lat_decisao_ms, lat_total_ms, rotulo)
                   VALUES (%(evento)s,%(username)s,%(sessao)s,%(ip)s,%(user_agent)s,%(recurso)s,%(hora)s,
                       %(score)s,%(decisao)s,%(motivo)s,%(fatores)s,%(eventos)s,%(lat_decisao_ms)s,
                       %(lat_total_ms)s,%(rotulo)s)""",
                {**kw, "fatores": Json(kw.get("fatores"))})
    except Exception:
        log.exception("Falha ao gravar auditoria")


def listar_auditoria(limite: int = 50) -> list[dict]:
    with cursor() as cur:
        cur.execute("SELECT id, ts, evento, username, ip, recurso, hora, score, decisao, motivo, "
                    "eventos, lat_decisao_ms, lat_total_ms, rotulo FROM auditoria "
                    "ORDER BY id DESC LIMIT %s", (min(max(limite, 1), 500),))
        return cur.fetchall()


def limpar_auditoria() -> None:
    with cursor() as cur:
        cur.execute("TRUNCATE auditoria RESTART IDENTITY")
