from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, asdict

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

SEED = 42
LIMIAR_NEGAR = float(os.getenv("ZT_LIMIAR_NEGAR", "0.7"))        # >= : NEGAR
LIMIAR_RESTRINGIR = float(os.getenv("ZT_LIMIAR_RESTRINGIR", "0.4"))  # >= : RESTRINGIR


# Atributos
# Ordem fixa do vetor de entrada da regressao logistica.
FEATURES = [
    "hora_sin", "hora_cos", "fora_expediente",          # horario
    "ip_externo", "ip_novo",                            # origem de rede
    "ip_mudou", "ua_mudou",                             # mudanca na sessao
    "ua_automatizado",                                  # tipo de cliente
    "sens_recurso", "margem_privilegio",                # privilegio x recurso
    "req_por_min", "recursos_distintos", "falhas_recentes", "anomalia",  # comportamento
]

# Agrupamento para explicabilidade: fator legivel -> atributos
GRUPOS = {
    "Horario de acesso": ["hora_sin", "hora_cos", "fora_expediente"],
    "Origem de rede (IP)": ["ip_externo", "ip_novo"],
    "Mudanca na sessao": ["ip_mudou", "ua_mudou"],
    "Tipo de cliente": ["ua_automatizado"],
    "Privilegio x recurso": ["sens_recurso", "margem_privilegio"],
    "Comportamento recente": ["req_por_min", "recursos_distintos",
                              "falhas_recentes", "anomalia"],
}

_UA_AUTOMATIZADO = re.compile(
    r"curl|wget|python|httpx|requests|aiohttp|scrapy|bot|crawl|spider|nmap|"
    r"sqlmap|nikto|go-http|java/|libwww|masscan", re.I)


def ua_automatizado(user_agent: str | None) -> int:
    #1 se o User-Agent e vazio ou tipico de ferramenta automatizada.
    if not user_agent or not user_agent.strip():
        return 1
    return int(bool(_UA_AUTOMATIZADO.search(user_agent)))


def _hora_ciclica(hora: int) -> tuple[float, float]:
    #Codificacao ciclica: 23h e 0h ficam proximos no espaco de atributos.
    ang = 2 * math.pi * (hora % 24) / 24
    return math.sin(ang), math.cos(ang)


def _fora_expediente(hora: int) -> int:
    return int(hora < 7 or hora >= 19)

# Contexto de uma requisicao (entrada do PDP)

@dataclass
class Contexto:
    hora: int                 # 0-23
    ip_externo: int           # 1 se fora das redes internas
    ip_novo: int              # 1 se IP nunca visto para o usuario
    ip_mudou: int             # 1 se IP difere do IP que abriu a sessao
    ua_mudou: int             # 1 se User-Agent difere do da abertura da sessao
    ua_automatizado: int      # 1 se cliente automatizado
    sens_recurso: int         # 0 (publico) .. 3 (critico)
    margem_privilegio: int    # privilegio atual da sessao - sensibilidade
    req_por_min: int          # requisicoes na ultima janela de 60 s
    recursos_distintos: int   # recursos distintos nos ultimos 5 min
    falhas_recentes: int      # negacoes/falhas nos ultimos 5 min


def _vetor_comportamento(c: dict) -> list[float]:
    """Entrada do detector de anomalias (so comportamento + horario)."""
    s, co = _hora_ciclica(c["hora"])
    return [c["req_por_min"], c["recursos_distintos"], s, co]


def _vetor(c: dict, anomalia: float) -> list[float]:
    s, co = _hora_ciclica(c["hora"])
    return [s, co, _fora_expediente(c["hora"]),
            c["ip_externo"], c["ip_novo"],
            c["ip_mudou"], c["ua_mudou"],
            c["ua_automatizado"],
            c["sens_recurso"], c["margem_privilegio"],
            c["req_por_min"], c["recursos_distintos"], c["falhas_recentes"],
            anomalia]

# Gerador de dados sinteticos (perfis de comportamento)

def _base(rng, hora, role, sens, **kw) -> dict:
    req = 1 + int(rng.poisson(kw.pop("lam_req", 3)))
    dist = min(1 + int(rng.poisson(kw.pop("lam_dist", 1.0))), 4, req)
    d = dict(hora=int(hora), ip_externo=0, ip_novo=0, ip_mudou=0, ua_mudou=0,
             ua_automatizado=0, sens_recurso=int(sens),
             margem_privilegio=int(role - sens), req_por_min=req,
             recursos_distintos=dist, falhas_recentes=int(rng.poisson(0.1)))
    d.update(kw)
    return d


def _legitimo(rng) -> dict:
    # 90% em horario comercial; 10% hora extra / inicio de manha
    if rng.random() < 0.10:
        hora = rng.choice([6, 19, 20, 21, 22])
    else:
        hora = int(np.clip(rng.normal(13, 2.8), 7, 18))
    role = int(rng.choice([1, 2, 3], p=[0.6, 0.3, 0.1]))
    # 3% de tentativas acidentais acima do privilegio
    sens = min(3, role + 1) if rng.random() < 0.03 else int(rng.integers(0, role + 1))
    return _base(rng, hora, role, sens,
                 ip_externo=int(rng.random() < 0.10),   # VPN / home office
                 ip_novo=int(rng.random() < 0.06),
                 ip_mudou=int(rng.random() < 0.03),     # roaming
                 ua_mudou=int(rng.random() < 0.01),
                 ua_automatizado=int(rng.random() < 0.02))  # integracoes


def _roubo_sessao(rng) -> dict:
    role = int(rng.choice([1, 2, 3], p=[0.6, 0.3, 0.1]))
    sens = int(rng.integers(1, 4))
    return _base(rng, rng.integers(0, 24), role, sens, lam_req=6, lam_dist=2,
                 ip_externo=int(rng.random() < 0.85), ip_novo=int(rng.random() < 0.9),
                 ip_mudou=1, ua_mudou=int(rng.random() < 0.85),
                 ua_automatizado=int(rng.random() < 0.15),
                 falhas_recentes=int(rng.poisson(0.6)))


def _credencial_vazada(rng) -> dict:
    role = int(rng.choice([1, 2, 3], p=[0.6, 0.3, 0.1]))
    hora = rng.integers(0, 6) if rng.random() < 0.7 else rng.integers(0, 24)
    return _base(rng, hora, role, rng.integers(0, 4), lam_req=20, lam_dist=2.5,
                 ip_externo=1, ip_novo=1, ua_automatizado=int(rng.random() < 0.9),
                 falhas_recentes=int(rng.poisson(2)))


def _escalada_privilegio(rng) -> dict:
    role = int(rng.choice([1, 2]))
    sens = min(3, role + 1 + int(rng.integers(0, 2)))
    return _base(rng, np.clip(rng.normal(13, 3), 7, 18), role, sens, lam_req=4,
                 lam_dist=2, ip_externo=int(rng.random() < 0.1),
                 ip_novo=int(rng.random() < 0.1),
                 falhas_recentes=int(rng.poisson(1.5)))


def _insider(rng) -> dict:
    role = int(rng.choice([2, 3]))
    return _base(rng, rng.integers(0, 6), role, rng.integers(max(1, role - 1), role + 1),
                 lam_req=12, lam_dist=2.5, ip_novo=int(rng.random() < 0.1),
                 ua_automatizado=int(rng.random() < 0.3),
                 falhas_recentes=int(rng.poisson(0.3)))


def _furtivo(rng) -> dict:
    #Ataque discreto: contexto legitimo com UMA unica anomalia (rotulo=risco).
    d = _legitimo(rng)
    d.update(rng.choice([
        {"ip_externo": 1, "ip_novo": 1}, {"ua_automatizado": 1},
        {"ip_mudou": 1, "ip_novo": 1}, {"hora": int(rng.integers(0, 5))},
    ]))
    return d


_ATAQUES = [_roubo_sessao, _credencial_vazada, _escalada_privilegio, _insider]


def gerar_dataset(n: int, rng, frac_ataque: float = 0.4):
    #Retorna (lista de contextos dict, vetor de rotulos 0/1).
    ctxs, y = [], []
    for _ in range(n):
        if rng.random() < frac_ataque:
            gen = _furtivo if rng.random() < 0.10 else _ATAQUES[int(rng.integers(len(_ATAQUES)))]
            ctxs.append(gen(rng)); y.append(1)
        else:
            ctxs.append(_legitimo(rng)); y.append(0)
    return ctxs, np.array(y)

# Treinamento (deterministico: SEED fixa)
def _escore_anomalia(detector: IsolationForest, ctxs: list[dict]) -> np.ndarray:
    X = np.array([_vetor_comportamento(c) for c in ctxs])
    return -detector.score_samples(X)          # ~0.4 normal ... >0.6 anomalo


def _metricas(y, prob, limiar) -> dict:
    pred = (prob >= limiar).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "limiar": limiar,
        "precisao": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred)), 4),
        "f1": round(float(f1_score(y, pred)), 4),
        "taxa_falso_positivo": round(float(fp / (fp + tn)), 4),
        "taxa_falso_negativo": round(float(fn / (fn + tp)), 4),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def _treinar():
    rng = np.random.default_rng(SEED)

    # 1) detector de anomalias: apenas comportamento legitimo (conjunto proprio)
    legit, _ = gerar_dataset(3000, rng, frac_ataque=0.0)
    # 40 arvores: ~3 ms por inferencia (150 arvores custavam ~12 ms sem ganho relevante)
    detector = IsolationForest(n_estimators=40, contamination="auto",
                               random_state=SEED)
    detector.fit(np.array([_vetor_comportamento(c) for c in legit]))

    # 2) classificador supervisionado
    ctxs, y = gerar_dataset(8000, rng)
    anom = _escore_anomalia(detector, ctxs)
    X = np.array([_vetor(c, a) for c, a in zip(ctxs, anom)])
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25,
                                          stratify=y, random_state=SEED)
    scaler = StandardScaler().fit(Xtr)
    clf = LogisticRegression(max_iter=2000, random_state=SEED)
    clf.fit(scaler.transform(Xtr), ytr)

    prob = clf.predict_proba(scaler.transform(Xte))[:, 1]
    # Baseline: regra fixa equivalente ao prototipo anterior (IP externo + cliente automatizado)
    i_ext, i_ua = FEATURES.index("ip_externo"), FEATURES.index("ua_automatizado")
    base_pred = ((Xte[:, i_ext] == 1) & (Xte[:, i_ua] == 1)).astype(float)

    info = {
        "amostras_treino": int(len(ytr)), "amostras_teste": int(len(yte)),
        "auc_roc": round(float(roc_auc_score(yte, prob)), 4),
        "teste_limiar_negar": _metricas(yte, prob, LIMIAR_NEGAR),
        "teste_limiar_restringir": _metricas(yte, prob, LIMIAR_RESTRINGIR),
        "baseline_regra_fixa": _metricas(yte, base_pred, 0.5),
        "coeficientes_padronizados": {f: round(float(w), 4)
                                      for f, w in zip(FEATURES, clf.coef_[0])},
        "intercepto": round(float(clf.intercept_[0]), 4),
        "aviso": "Metricas obtidas em dados sinteticos gerados pelos mesmos perfis do treino.",
    }
    return detector, scaler, clf, info


DETECTOR, SCALER, MODELO, INFO_MODELO = _treinar()

# Inferencia + explicabilidade
@dataclass
class Fator:
    nome: str
    valor: str            # descricao legivel do valor observado
    contribuicao: float   # contribuicao ao logit (>0 aumenta o risco)


@dataclass
class Avaliacao:
    score: float
    anomalia: float
    fatores: list[Fator]
    explicacao: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = round(self.score, 4)
        d["anomalia"] = round(self.anomalia, 4)
        for f in d["fatores"]:
            f["contribuicao"] = round(f["contribuicao"], 3)
        return d


def _descrever(grupo: str, c: dict) -> str:
    if grupo == "Horario de acesso":
        return f"{c['hora']:02d}h" + (" (fora do expediente)" if _fora_expediente(c["hora"]) else "")
    if grupo == "Origem de rede (IP)":
        return ("externo" if c["ip_externo"] else "interno") + (", inedito" if c["ip_novo"] else ", conhecido")
    if grupo == "Mudanca na sessao":
        mud = [n for n, k in (("IP alterado", "ip_mudou"), ("User-Agent alterado", "ua_mudou")) if c[k]]
        return ", ".join(mud) if mud else "sem alteracao"
    if grupo == "Tipo de cliente":
        return "automatizado" if c["ua_automatizado"] else "navegador"
    if grupo == "Privilegio x recurso":
        return f"sensibilidade {c['sens_recurso']}, margem {c['margem_privilegio']}"
    return (f"{c['req_por_min']} req/min, {c['recursos_distintos']} recursos, "
            f"{c['falhas_recentes']} falhas")


def avaliar_risco(ctx: Contexto | dict) -> Avaliacao:
    """Calcula o escore de risco (0-1) e os fatores que mais contribuiram."""
    c = asdict(ctx) if isinstance(ctx, Contexto) else dict(ctx)
    anom = float(_escore_anomalia(DETECTOR, [c])[0])
    x = np.array([_vetor(c, anom)])
    z = SCALER.transform(x)[0]
    contrib = MODELO.coef_[0] * z                      # contribuicao exata ao logit
    score = float(MODELO.predict_proba(z.reshape(1, -1))[0, 1])

    idx = {f: i for i, f in enumerate(FEATURES)}
    fatores = [Fator(g, _descrever(g, c), float(sum(contrib[idx[f]] for f in fs)))
               for g, fs in GRUPOS.items()]
    fatores.sort(key=lambda f: f.contribuicao, reverse=True)

    principais = [f for f in fatores if f.contribuicao > 0.15][:3]
    if principais:
        txt = "; ".join(f"{f.nome}: {f.valor} (+{f.contribuicao:.2f})" for f in principais)
        explicacao = f"Risco {score:.2f} puxado por: {txt}."
    else:
        explicacao = f"Risco {score:.2f}: nenhum fator relevante elevou o risco."
    return Avaliacao(score, anom, fatores, explicacao)


def nivel_decisao(score: float) -> str:
    if score >= LIMIAR_NEGAR:
        return "NEGAR"
    if score >= LIMIAR_RESTRINGIR:
        return "RESTRINGIR"
    return "PERMITIR"


if __name__ == "__main__":      # python -m app.ia  -> imprime metricas do modelo
    import json
    print(json.dumps(INFO_MODELO, indent=2, ensure_ascii=False))
