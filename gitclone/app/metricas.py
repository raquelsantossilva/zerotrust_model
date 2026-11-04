from __future__ import annotations

import threading
from collections import Counter

import numpy as np


class Metricas:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.resetar()

    def resetar(self) -> None:
        with self._lock:
            self.c: Counter = Counter()
            self.lat_decisao: list[float] = []
            self.lat_total: list[float] = []

    def contar(self, nome: str) -> None:
        with self._lock:
            self.c[nome] += 1

    def registrar(self, decisao: str, rotulo: str | None, eventos: list[str],
                  lat_decisao_ms: float, lat_total_ms: float, motivo: str | None = None) -> None:
        with self._lock:
            self.c["total"] += 1
            if motivo == "sessao_revogada":
                self.c["negadas_por_sessao_revogada"] += 1
            self.c[decisao.lower()] += 1
            for ev in eventos:
                self.c[ev.split(":")[0].lower()] += 1       # privilegio_reduzido, ...
            if rotulo == "malicioso":
                self.c["rotulo_malicioso"] += 1
                if decisao in ("NEGAR", "RESTRINGIR"):
                    self.c["bloqueios_corretos"] += 1
                else:
                    self.c["falsos_negativos"] += 1
            elif rotulo == "legitimo":
                self.c["rotulo_legitimo"] += 1
                if decisao == "NEGAR":
                    self.c["falsos_positivos"] += 1
                elif decisao == "RESTRINGIR":
                    self.c["restricoes_indevidas"] += 1
                else:
                    self.c["legitimos_permitidos"] += 1
            else:
                self.c["sem_rotulo"] += 1
            self.lat_decisao.append(lat_decisao_ms)
            self.lat_total.append(lat_total_ms)

    @staticmethod
    def _stats(v: list[float]) -> dict:
        if not v:
            return {"n": 0}
        a = np.array(v)
        return {"n": len(v), "media_ms": round(float(a.mean()), 3),
                "p50_ms": round(float(np.percentile(a, 50)), 3),
                "p95_ms": round(float(np.percentile(a, 95)), 3),
                "p99_ms": round(float(np.percentile(a, 99)), 3),
                "max_ms": round(float(a.max()), 3)}

    def resumo(self) -> dict:
        with self._lock:
            c = self.c
            mal, leg = c["rotulo_malicioso"], c["rotulo_legitimo"]
            bc, fn, fp = c["bloqueios_corretos"], c["falsos_negativos"], c["falsos_positivos"]
            return {
                "totais": {k: c[k] for k in ("total", "permitir", "restringir", "negar", "sem_rotulo")},
                "negadas_por_sessao_revogada": c["negadas_por_sessao_revogada"],
                "credenciais_invalidas": c["credenciais_invalidas"],
                "alteracoes_privilegio": {
                    "reducoes": c["privilegio_reduzido"],
                    "restauracoes": c["privilegio_restaurado"],
                    "sessoes_revogadas": c["sessao_revogada"]},
                "avaliacao_rotulada": {
                    "acessos_indevidos_bloqueados": bc,
                    "acessos_indevidos_que_passaram": fn,
                    "legitimos_bloqueados_falsos_positivos": fp,
                    "legitimos_com_privilegio_reduzido": c["restricoes_indevidas"],
                    "legitimos_permitidos": c["legitimos_permitidos"],
                    "taxa_bloqueio_correto": round(bc / mal, 4) if mal else None,
                    "taxa_falso_positivo": round(fp / leg, 4) if leg else None,
                    "precisao_bloqueio": round(bc / (bc + fp + c["restricoes_indevidas"]), 4)
                    if (bc + fp + c["restricoes_indevidas"]) else None,
                },
                "latencia_decisao_modelo": self._stats(self.lat_decisao),
                "latencia_resposta_total": self._stats(self.lat_total),
            }


METRICAS = Metricas()
