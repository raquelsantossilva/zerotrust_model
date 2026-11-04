proxy.py - Policy Enforcement Point (PEP) Zero Trust.



Fluxo de CADA requisicao a um recurso (nunca ha "confianca herdada"):



&#x20; 1. identifica a sessao (Bearer token)            -> 401 se ausente/revogada

&#x20; 2. monta o contexto (horario, IP, User-Agent, mudanca desde a abertura da

&#x20;    sessao, recurso/sensibilidade, privilegio corrente, comportamento recente)

&#x20; 3. consulta o PDP (ia.avaliar\_risco)             -> escore + fatores explicativos

&#x20; 4. decide: PERMITIR | RESTRINGIR | NEGAR         (limiares 0.4 / 0.7)

&#x20; 5. REAVALIA a confianca da sessao: reduz/restaura privilegio, pode revogar

&#x20; 6. so entao consulta o PostgreSQL                (dados so apos a decisao)

&#x20; 7. audita (PostgreSQL) e atualiza metricas



Modo simulacao (ZT\_SIMULATION=1): aceita cabecalhos X-Simulated-IP,

X-Simulated-Hour e X-Scenario-Label para reproduzir cenarios e medir falsos

positivos/negativos. DESLIGADO por padrao: em producao esses cabecalhos seriam

um vetor de spoofing e sao ignorados.



\---------------------------------

ia.py - Motor de decisão de risco (PDP / Policy Engine) do prototipo Zero Trust.



Combina dois modelos:

&#x20; 1. IsolationForest (nao supervisionado): detecta ANOMALIAS de comportamento

&#x20;    recente (taxa de requisicoes, variedade de recursos, horario), treinado

&#x20;    apenas com comportamento legitimo.

&#x20; 2. Regressao Logistica (supervisionada): classifica o contexto completo da

&#x20;    requisicao e devolve P(risco). O escore de anomalia do item 1 entra como

&#x20;    um de seus atributos.



Explicabilidade: como o modelo final e linear sobre atributos padronizados,

a contribuicao de cada atributo ao logit e exata (coef\_i \* z\_i). Os atributos

sao agrupados em 6 fatores legiveis (horario, origem do IP, mudanca na sessao,

tipo de cliente, privilegio x recurso, comportamento recente).



ATENCAO (validade): os dados de treino sao SINTETICOS, gerados por perfis

(legitimo, roubo de sessao, credencial vazada, escalada de privilegio, insider).

As metricas de teste medem o quanto o modelo aprendeu esses perfis, nao o

desempenho em trafego real. Veja a secao de ameacas a validade do relatorio.



\---------------------------------

db.py - Camada de dados PostgreSQL (substitui o antigo conection.py).



Correcoes em relacao a versao anterior:

&#x20; \* pool de conexoes (antes: UMA conexao global, fechada no `finally`, o que

&#x20;   quebrava a segunda requisicao);

&#x20; \* criacao de esquema/seed IDEMPOTENTE e chamada explicitamente na

&#x20;   inicializacao (antes: o INSERT rodava a cada import e duplicava dados);

&#x20; \* credenciais por variavel de ambiente (antes: senha no codigo);

&#x20; \* consultas parametrizadas (sem concatenar strings => sem SQL injection);

&#x20; \* trilha de auditoria persistente de cada decisao.



\---------------------------------

metricas.py - Coleta das metricas de avaliacao exigidas pelo Projeto 6.



&#x20; \* acessos indevidos bloqueados   (verdadeiros positivos)

&#x20; \* usuarios legitimos bloqueados  (falsos positivos)

&#x20; \* tempo de decisao               (inferencia e resposta total)

&#x20; \* alteracoes de privilegio / negacoes / revogacoes



Rotulos (legitimo | malicioso) so existem em MODO SIMULACAO, pois a verdade

de campo so e conhecida quando nos mesmos geramos o trafego. Em producao

as requisicoes ficam "sem\_rotulo" e apenas contagens e latencias sao validas.



Definicoes:

&#x20; malicioso + (RESTRINGIR ou NEGAR)  -> bloqueio correto (mitigado)

&#x20; malicioso + PERMITIR               -> falso negativo (ataque passou)

&#x20; legitimo  + NEGAR                  -> falso positivo (bloqueio indevido)

&#x20; legitimo  + RESTRINGIR             -> restricao indevida (privilegio reduzido

&#x20;                                       sem necessidade; contada a parte)



\---------------------------------

sessoes.py - Estado de sessao e historico de comportamento (alimenta o PDP).



Zero Trust exige reavaliar a confianca a CADA requisicao. Este modulo guarda,

por sessao:

&#x20; \* fingerprint de abertura (IP, User-Agent) -> detecta roubo de sessao;

&#x20; \* janelas deslizantes (taxa de requisicoes, recursos distintos, negacoes);

&#x20; \* nivel de confianca (media movel exponencial do risco observado);

&#x20; \* privilegio corrente, que pode ser REDUZIDO (e depois restaurado) conforme

&#x20;   o risco, e a revogacao da sessao quando a confianca cai demais.



Armazenamento em memoria (suficiente para o prototipo; para varios workers /

replicas, trocar por Redis).



\---------------------------------

simular.py - Cenarios de teste do Projeto 6 (Etapas 6 e 8 do PDF).



Executa contra a API em ZT\_SIMULATION=1:



&#x20; C1  legitimo\_comercial      usuarios reais, IP conhecido, 8h-17h, recursos permitidos

&#x20; C2  legitimo\_fim\_expediente usuarios legitimos 19h-21h (teste de falso positivo)

&#x20; C3  roubo\_de\_sessao         token de vitima reutilizado de outro IP/UA, de madrugada

&#x20; C4  credencial\_vazada       senha correta usada de IP externo, curl, madrugada, em rajada

&#x20; C5  forca\_bruta             varias senhas erradas e depois a correta (mesmo IP)

&#x20; C6  escalada\_privilegio     usuario interno pede recursos acima da sua role

&#x20; C7  insider\_madrugada       analista/admin interno acessando em rajada fora de hora

&#x20; C8  reavaliacao\_na\_sessao   linha do tempo: sessao legitima que e sequestrada no meio



Cada requisicao e rotulada (legitimo/malicioso) via X-Scenario-Label para que o

proxy compute bloqueios corretos, falsos positivos e falsos negativos.

Dados brutos de todas as requisicoes sao gravados em CSV.



Uso:  python simular.py --url http://localhost:8082 --repeticoes 5 --seed 7



\---------------------------------



