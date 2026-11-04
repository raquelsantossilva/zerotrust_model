#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
import sys
import time

import httpx

NAVEGADOR = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
NAVEGADOR_ATACANTE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"
USUARIOS = {  # usuario: (role, IP habitual)
    "ana": ("viewer", "10.0.0.11"), "bruno": ("analista", "10.0.0.12"),
    "carla": ("admin", "10.0.0.13"), "diego": ("analista", "10.0.0.14"),
    "eva": ("viewer", "10.0.0.15"),
}
CLEARANCE = {"viewer": 1, "analista": 2, "admin": 3}
RECURSOS = {"publico": 0, "redes": 1, "financeiro": 2, "admin_config": 3}
SENHA = "demo123"


class Sim:
    def __init__(self, base_url: str, rng: random.Random, pausa: float):
        self.http = httpx.Client(base_url=base_url, timeout=15)
        self.rng, self.pausa = rng, pausa
        self.linhas: list[dict] = []          # dados brutos
        self.cenario = ""

    # helpers
    def _h(self, ip, hora, ua, rotulo, token=None):
        h = {"X-Simulated-IP": ip, "X-Simulated-Hour": str(hora),
             "X-Scenario-Label": rotulo, "User-Agent": ua}
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    def _log(self, rotulo, tipo, alvo, r):
        try:
            b = r.json()
        except Exception:
            b = {}
        b = b if isinstance(b, dict) else {}
        self.linhas.append({
            "cenario": self.cenario, "rotulo": rotulo, "tipo": tipo, "alvo": alvo,
            "http": r.status_code, "decisao": b.get("decisao") or
            ("NEGAR" if r.status_code == 401 else ""),
            "motivo": b.get("motivo", b.get("detail", "")), "score": b.get("score", ""),
            "confianca": b.get("nivel_confianca", ""), "privilegio": b.get("privilegio_atual", ""),
            "eventos": "|".join(b.get("eventos", [])),
            "lat_decisao_ms": r.headers.get("x-decision-time-ms", "")})
        time.sleep(self.pausa)
        return b

    def login(self, user, senha, ip, hora, ua, rotulo):
        r = self.http.post("/login", json={"username": user, "password": senha},
                           headers=self._h(ip, hora, ua, rotulo))
        b = self._log(rotulo, "login", user, r)
        return b.get("session_token"), b

    def acessar(self, token, recurso, ip, hora, ua, rotulo):
        r = self.http.get(f"/recurso/{recurso}", headers=self._h(ip, hora, ua, rotulo, token))
        return self._log(rotulo, "acesso", recurso, r)

    def permitidos(self, role):
        return [n for n, s in RECURSOS.items() if s <= CLEARANCE[role]]

    # cenarios
    def c1_legitimo_comercial(self, n=40):
        self.cenario = "C1_legitimo_comercial"
        for _ in range(n):
            u = self.rng.choice(list(USUARIOS)); role, ip = USUARIOS[u]
            hora = self.rng.randint(8, 17)
            tok, _ = self.login(u, SENHA, ip, hora, NAVEGADOR, "legitimo")
            for _ in range(self.rng.randint(3, 5)):
                if tok:
                    self.acessar(tok, self.rng.choice(self.permitidos(role)), ip, hora, NAVEGADOR, "legitimo")
            time.sleep(self.pausa * 4)

    def c2_legitimo_fim_expediente(self, n=10):
        self.cenario = "C2_legitimo_fim_expediente"
        for _ in range(n):
            u = self.rng.choice(list(USUARIOS)); role, ip = USUARIOS[u]
            hora = self.rng.choice([19, 20, 21])
            tok, _ = self.login(u, SENHA, ip, hora, NAVEGADOR, "legitimo")
            for _ in range(3):
                if tok:
                    self.acessar(tok, self.rng.choice(self.permitidos(role)), ip, hora, NAVEGADOR, "legitimo")
            time.sleep(self.pausa * 4)

    def c3_roubo_de_sessao(self, n=15):
        self.cenario = "C3_roubo_de_sessao"
        for _ in range(n):
            u = self.rng.choice(list(USUARIOS)); role, ip = USUARIOS[u]
            tok, _ = self.login(u, SENHA, ip, 11, NAVEGADOR, "legitimo")     # vitima
            if not tok:
                continue
            self.acessar(tok, "publico", ip, 11, NAVEGADOR, "legitimo")
            ip_at = f"203.0.113.{self.rng.randint(2, 250)}"                  # atacante
            for _ in range(5):
                self.acessar(tok, self.rng.choice(self.permitidos(role)), ip_at,
                             self.rng.randint(0, 5), NAVEGADOR_ATACANTE, "malicioso")
            time.sleep(self.pausa * 4)

    def c4_credencial_vazada(self, n=15):
        self.cenario = "C4_credencial_vazada"
        for _ in range(n):
            u = self.rng.choice(list(USUARIOS)); role, _ = USUARIOS[u]
            ip_at = f"198.51.100.{self.rng.randint(2, 250)}"
            hora = self.rng.randint(1, 4)
            tok, _ = self.login(u, SENHA, ip_at, hora, "curl/8.5.0", "malicioso")
            for _ in range(12):
                if not tok:
                    break
                self.acessar(tok, self.rng.choice(self.permitidos(role)), ip_at, hora, "curl/8.5.0", "malicioso")
            time.sleep(self.pausa * 4)

    def c5_forca_bruta(self, n=8):
        self.cenario = "C5_forca_bruta"
        for _ in range(n):
            u = self.rng.choice(list(USUARIOS)); ip_at = f"192.0.2.{self.rng.randint(2, 250)}"
            hora = self.rng.randint(0, 23)
            for i in range(8):
                self.login(u, f"errada{i}", ip_at, hora, "python-requests/2.31", "malicioso")
            self.login(u, SENHA, ip_at, hora, "python-requests/2.31", "malicioso")  # a correta

    def c6_escalada_privilegio(self, n=10):
        self.cenario = "C6_escalada_privilegio"
        for _ in range(n):
            u = self.rng.choice(["ana", "eva", "bruno", "diego"]); role, ip = USUARIOS[u]
            hora = self.rng.randint(9, 16)
            tok, _ = self.login(u, SENHA, ip, hora, NAVEGADOR, "legitimo")
            acima = [r for r, s in RECURSOS.items() if s > CLEARANCE[role]]
            for _ in range(4):
                if tok:
                    self.acessar(tok, self.rng.choice(acima), ip, hora, NAVEGADOR, "malicioso")
            time.sleep(self.pausa * 4)

    def c7_insider_madrugada(self, n=10):
        self.cenario = "C7_insider_madrugada"
        for _ in range(n):
            u = self.rng.choice(["bruno", "carla", "diego"]); role, ip = USUARIOS[u]
            hora = self.rng.randint(1, 4)
            tok, _ = self.login(u, SENHA, ip, hora, NAVEGADOR, "malicioso")
            for _ in range(12):
                if tok:
                    self.acessar(tok, self.rng.choice(self.permitidos(role)), ip, hora, NAVEGADOR, "malicioso")
            time.sleep(self.pausa * 4)

    def c8_reavaliacao(self):
        #Linha do tempo de UMA sessao: confianca/privilegio mudam ao longo do uso.
        self.cenario = "C8_reavaliacao_na_sessao"
        u, (role, ip) = "bruno", USUARIOS["bruno"]
        tok, _ = self.login(u, SENHA, ip, 10, NAVEGADOR, "legitimo")
        linha = []
        for i in range(4):                                                  # uso normal
            b = self.acessar(tok, self.rng.choice(self.permitidos(role)), ip, 10, NAVEGADOR, "legitimo")
            linha.append(("legitimo", ip, b))
        ip_at = "203.0.113.77"
        for i in range(8):                                                  # sequestro
            b = self.acessar(tok, "financeiro", ip_at, 3, NAVEGADOR_ATACANTE, "malicioso")
            linha.append(("malicioso", ip_at, b))
        return linha


BATERIA = ["c1_legitimo_comercial", "c2_legitimo_fim_expediente", "c3_roubo_de_sessao",
           "c4_credencial_vazada", "c5_forca_bruta", "c6_escalada_privilegio",
           "c7_insider_madrugada"]


def resumo_cenarios(linhas):
    #Tabela por cenario: contagem de decisoes das requisicoes de acesso/login.
    por = {}
    for l in linhas:
        if l["motivo"] == "credenciais_invalidas":
            d = por.setdefault(l["cenario"], {"PERMITIR": 0, "RESTRINGIR": 0, "NEGAR": 0, "senha_errada": 0})
            d["senha_errada"] += 1
            continue
        d = por.setdefault(l["cenario"], {"PERMITIR": 0, "RESTRINGIR": 0, "NEGAR": 0, "senha_errada": 0})
        if l["decisao"] in d:
            d[l["decisao"]] += 1
    return por


def executar(url, seed, pausa):
    sim = Sim(url, random.Random(seed), pausa)
    sim.http.post("/simulacao/reset").raise_for_status()
    for nome in BATERIA:
        getattr(sim, nome)()
    linha_tempo = sim.c8_reavaliacao()
    metricas = sim.http.get("/metricas").json()
    return sim.linhas, linha_tempo, metricas


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8082")
    ap.add_argument("--repeticoes", type=int, default=3)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--pausa", type=float, default=0.02, help="s entre requisicoes")
    ap.add_argument("--saida", default="resultados")
    a = ap.parse_args()

    try:
        httpx.get(f"{a.url}/health", timeout=5).raise_for_status()
    except Exception as e:
        sys.exit(f"API indisponivel em {a.url}: {e}")

    todas, rep_metricas = [], []
    for r in range(a.repeticoes):
        linhas, tempo, m = executar(a.url, a.seed + r, a.pausa)
        for l in linhas:
            l["repeticao"] = r
        todas += linhas
        rep_metricas.append(m)
        av = m["avaliacao_rotulada"]
        print(f"[rep {r}] bloqueio_correto={av['taxa_bloqueio_correto']}  FP={av['taxa_falso_positivo']}"
              f"  FN={av['acessos_indevidos_que_passaram']}  lat_decisao_p50={m['latencia_decisao_modelo']['p50_ms']} ms")

    # resultados da ultima repeticao em detalhe
    print("\n=== Decisoes por cenario (todas as repeticoes) ===")
    print(f"{'cenario':30s} {'PERMITIR':>9s} {'RESTRINGIR':>11s} {'NEGAR':>7s} {'senha_errada':>13s}")
    for c, d in sorted(resumo_cenarios(todas).items()):
        print(f"{c:30s} {d['PERMITIR']:9d} {d['RESTRINGIR']:11d} {d['NEGAR']:7d} {d['senha_errada']:13d}")

    print("\n=== C8: reavaliacao continua durante uma sessao (ultima repeticao) ===")
    print(f"{'#':>2s} {'origem':10s} {'ip':16s} {'decisao':10s} {'score':>6s} {'confianca':>9s} {'priv':>4s}  eventos")
    for i, (rot, ip, b) in enumerate(tempo, 1):
        print(f"{i:2d} {rot:10s} {ip:16s} {str(b.get('decisao') or 'NEGAR*'):10s} "
              f"{str(b.get('score', '-')):>6s} {str(b.get('nivel_confianca', '-')):>9s} "
              f"{str(b.get('privilegio_atual', '-')):>4s}  {','.join(b.get('eventos', []))}")

    def agrega(fn):
        v = [fn(m) for m in rep_metricas if fn(m) is not None]
        return (round(statistics.mean(v), 4), round(statistics.pstdev(v), 4)) if v else None

    agg = {
        "repeticoes": a.repeticoes,
        "taxa_bloqueio_correto": agrega(lambda m: m["avaliacao_rotulada"]["taxa_bloqueio_correto"]),
        "taxa_falso_positivo": agrega(lambda m: m["avaliacao_rotulada"]["taxa_falso_positivo"]),
        "falsos_negativos_por_rep": agrega(lambda m: m["avaliacao_rotulada"]["acessos_indevidos_que_passaram"]),
        "restricoes_indevidas_por_rep": agrega(lambda m: m["avaliacao_rotulada"]["legitimos_com_privilegio_reduzido"]),
        "lat_decisao_p50_ms": agrega(lambda m: m["latencia_decisao_modelo"]["p50_ms"]),
        "lat_decisao_p95_ms": agrega(lambda m: m["latencia_decisao_modelo"]["p95_ms"]),
        "lat_resposta_p50_ms": agrega(lambda m: m["latencia_resposta_total"]["p50_ms"]),
        "lat_resposta_p95_ms": agrega(lambda m: m["latencia_resposta_total"]["p95_ms"]),
    }
    print("(* NEGAR* = sessao ja revogada: 401 sem nova avaliacao)")
    print("\n=== Agregado (media, desvio-padrao) ===")
    for k, v in agg.items():
        print(f"{k:32s} {v}")

    # ---- dados brutos preservados
    with open(f"{a.saida}_requisicoes.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(todas[0].keys()))
        w.writeheader(); w.writerows(todas)
    with open(f"{a.saida}_metricas.json", "w", encoding="utf-8") as f:
        json.dump({"agregado": agg, "por_repeticao": rep_metricas}, f, indent=2, ensure_ascii=False)
    print(f"\nDados brutos: {a.saida}_requisicoes.csv | metricas: {a.saida}_metricas.json")


if __name__ == "__main__":
    main()
