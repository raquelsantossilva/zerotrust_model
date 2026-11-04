from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

CLEARANCE = {"viewer": 1, "analista": 2, "admin": 3}   # role -> sensibilidade maxima

TTL_ABSOLUTO_S = 8 * 3600       # sessao expira em 8 h
TTL_OCIOSO_S = 30 * 60          # ... ou apos 30 min sem uso
JANELA_TAXA_S = 60
JANELA_COMPORTAMENTO_S = 300
ALFA_CONFIANCA = 0.5            # peso da observacao mais recente no EMA
LIMIAR_REVOGACAO = 0.25         # confianca abaixo disso => sessao revogada
PERMITIDOS_PARA_RESTAURAR = 5   # acessos seguidos de baixo risco restauram 1 nivel


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class Sessao:
    id_hash: str
    username: str
    role: str
    clearance: int                 # teto de privilegio da role
    privilegio: int                # privilegio corrente (<= clearance)
    ip_inicial: str
    ua_inicial: str
    criada_em: float
    ultimo_uso: float
    ips_conhecidos: frozenset = frozenset()   # IPs historicos do usuario
    confianca: float = 1.0         # 1 = totalmente confiavel
    revogada: bool = False
    seguidos_baixo_risco: int = 0
    reqs: deque = field(default_factory=deque)       # timestamps
    recursos: deque = field(default_factory=deque)   # (timestamp, recurso)
    negacoes: deque = field(default_factory=deque)   # timestamps


class GerenciadorSessoes:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessoes: dict[str, Sessao] = {}
        self._logins: dict[str, deque] = defaultdict(deque)   # ip -> (ts, ok)

    # ciclo
    def criar(self, username: str, role: str, ip: str, ua: str,
              ips_conhecidos=(), privilegio_inicial: int | None = None) -> tuple[str, Sessao]:
        token = secrets.token_urlsafe(32)
        agora = time.time()
        clr = CLEARANCE.get(role, 1)
        priv = clr if privilegio_inicial is None else max(0, min(clr, privilegio_inicial))
        s = Sessao(hash_token(token), username, role, clr, priv, ip, ua, agora, agora,
                   frozenset(ips_conhecidos))
        with self._lock:
            self._sessoes[s.id_hash] = s
        return token, s

    def obter(self, token: str) -> Sessao | None:
        agora = time.time()
        with self._lock:
            s = self._sessoes.get(hash_token(token))
            if s is None:
                return None
            if agora - s.criada_em > TTL_ABSOLUTO_S or agora - s.ultimo_uso > TTL_OCIOSO_S:
                s.revogada = True
            return s

    def encerrar(self, s: Sessao) -> None:
        with self._lock:
            s.revogada = True

    # janelas
    @staticmethod
    def _podar(s: Sessao, agora: float) -> None:
        while s.reqs and agora - s.reqs[0] > JANELA_COMPORTAMENTO_S:
            s.reqs.popleft()
        while s.recursos and agora - s.recursos[0][0] > JANELA_COMPORTAMENTO_S:
            s.recursos.popleft()
        while s.negacoes and agora - s.negacoes[0] > JANELA_COMPORTAMENTO_S:
            s.negacoes.popleft()

    def registrar_requisicao(self, s: Sessao, recurso: str) -> dict:
        """Registra a requisicao atual e devolve as metricas de comportamento."""
        agora = time.time()
        with self._lock:
            s.ultimo_uso = agora
            s.reqs.append(agora)
            s.recursos.append((agora, recurso))
            self._podar(s, agora)
            return {
                "req_por_min": sum(1 for t in s.reqs if agora - t <= JANELA_TAXA_S),
                "recursos_distintos": len({r for _, r in s.recursos}),
                "falhas_recentes": len(s.negacoes),
            }

    # reavaliacao continua
    def aplicar_decisao(self, s: Sessao, decisao: str, score: float) -> list[str]:
        #Atualiza confianca e privilegio apos uma decisao. Retorna a lista de eventos gerados (alteracao de privilegio / revogacao) para auditoria.
        eventos: list[str] = []
        with self._lock:
            s.confianca = (1 - ALFA_CONFIANCA) * s.confianca + ALFA_CONFIANCA * (1 - score)

            if decisao == "NEGAR":
                s.negacoes.append(time.time())
            if decisao == "PERMITIR":
                s.seguidos_baixo_risco += 1
            else:
                s.seguidos_baixo_risco = 0

            if decisao == "RESTRINGIR" and s.privilegio > 0:
                s.privilegio -= 1
                eventos.append(f"PRIVILEGIO_REDUZIDO:{s.privilegio + 1}->{s.privilegio}")
            elif (decisao == "PERMITIR" and s.privilegio < s.clearance
                  and s.seguidos_baixo_risco >= PERMITIDOS_PARA_RESTAURAR):
                s.privilegio += 1
                s.seguidos_baixo_risco = 0
                eventos.append(f"PRIVILEGIO_RESTAURADO:{s.privilegio - 1}->{s.privilegio}")

            if s.confianca < LIMIAR_REVOGACAO and not s.revogada:
                s.revogada = True
                eventos.append(f"SESSAO_REVOGADA:confianca={s.confianca:.2f}")
        return eventos

    # tentativas
    def contexto_login(self, ip: str) -> dict:
        """Taxa de tentativas e falhas de login recentes para um IP."""
        agora = time.time()
        with self._lock:
            q = self._logins[ip]
            while q and agora - q[0][0] > JANELA_COMPORTAMENTO_S:
                q.popleft()
            return {
                "req_por_min": 1 + sum(1 for t, _ in q if agora - t <= JANELA_TAXA_S),
                "recursos_distintos": 1,
                "falhas_recentes": sum(1 for _, ok in q if not ok),
            }

    def registrar_login(self, ip: str, ok: bool) -> None:
        with self._lock:
            self._logins[ip].append((time.time(), ok))

    def limpar(self) -> None:
        with self._lock:
            self._sessoes.clear()
            self._logins.clear()


SESSOES = GerenciadorSessoes()
