# Projeto 6 — Controle de Acesso Contínuo Zero Trust (v2)

```
cliente ──► proxy.py (PEP) ──► ia.py (PDP: Isolation Forest + Regressão Logística + explicação)
                │                       │
                │  sessoes.py: janelas de comportamento, confiança (EMA), privilégio, revogação
                ▼
         db.py ► PostgreSQL (rede interna): usuarios, recursos, redes, auditoria
         metricas.py ► /metricas   |   simular.py ► cenários C1..C8
```

## Executar
```bash
docker compose up --build                                   # API em http://localhost:8082
docker compose --profile simulacao run --rm simulador       # cenários; saída em ./saida/
# ou, local (com um PostgreSQL acessível):
POSTGRES_HOST=localhost POSTGRES_PASSWORD=... ZT_SIMULATION=1 uvicorn app.proxy:app --port 8082
python simular.py --url http://localhost:8082 --repeticoes 5
pytest -v
python -m app.ia          # métricas do modelo em dados de teste sintéticos
```
Usuários de demonstração: ana/eva (viewer), bruno/diego (analista), carla (admin) — senha `demo123` (`ZT_DEMO_PASSWORD`).
Recursos: `publico`(0) `redes`(1) `financeiro`(2) `admin_config`(3).

## Endpoints
| Método | Rota | Função |
|---|---|---|
| POST | `/login` | autenticação **avaliada pelo PDP** (retorna `session_token`) |
| GET | `/recurso/{nome}` | acesso com reavaliação de risco a cada chamada (`Authorization: Bearer`) |
| GET | `/sessao`, POST `/logout` | introspecção / encerramento |
| GET | `/metricas`, `/auditoria`, `/modelo` | métricas do projeto, trilha de auditoria, explicabilidade global |
| POST | `/simulacao/reset` | zera estado (apenas com `ZT_SIMULATION=1`) |

## Variáveis de ambiente
`POSTGRES_*`, `ZT_SIMULATION` (0/1), `ZT_LIMIAR_NEGAR` (0.7), `ZT_LIMIAR_RESTRINGIR` (0.4),
`ZT_INTERNAL_NETS`, `ZT_TRUST_XFF`, `ZT_EXPLAIN_TO_CLIENT`, `ZT_TZ`, `ZT_DEMO_PASSWORD`.

## Aviso
`ZT_SIMULATION=1` aceita cabeçalhos que forjam IP/hora/rótulo — **apenas para experimentos**.
Os dados de treino são sintéticos; as métricas não representam tráfego real.
