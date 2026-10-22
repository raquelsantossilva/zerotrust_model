import numpy as np
from datetime import datetime
from sklearn.linear_model import LogisticRegression

# Matriz de treino com as 6 amostras completas
# Formato de cada linha: [hora, is_local_ip, is_normal_browser]
X_treino = np.array([
    [10, 1, 1],  # Horário comercial, IP local, Navegador -> SEGURO (0)
    [14, 1, 1],  # Horário comercial, IP local, Navegador -> SEGURO (0)
    [3, 0, 0],   # Madrugada, IP externo, Via Curl -> PERIGOSO (1)
    [22, 0, 1],  # Noite, IP externo, Navegador -> PERIGOSO (1)
    [11, 0, 0],  # Horário comercial, IP externo, Via Curl -> PERIGOSO (1)
    [16, 1, 1]   # Horário comercial, IP local, Navegador -> SEGURO (0)
])

# Vetor de respostas correto para as 6 amostras acima
y_treino = np.array([0, 0, 1, 1, 1, 0])

# Inicializa e treina o modelo no escopo global
ia_zero_trust = LogisticRegression()
ia_zero_trust.fit(X_treino, y_treino)


def regression_model_zero_trust(pilares):
    """
    Função que avalia o risco usando o modelo treinado de Regressão Logística.
    """
    # 1. Trata o pilar: HORA
    hora_acesso = pilares.get("hora")
    if isinstance(hora_acesso, datetime):
        hora_num = hora_acesso.hour
    else:
        hora_num = datetime.now().hour
    
    # 2. Trata o pilar: IP (1 se local, 0 se externo)
    ip_cliente = pilares.get("ip", "desconhecido")
    is_local_ip = 1 if (ip_cliente in ["127.0.0.1", "localhost", "testclient"] or ip_cliente.startswith("172.")) else 0    
    # 3. Trata o pilar: USER-AGENT (1 se navegador comum, 0 se curl/automador)
    user_agent = pilares.get("user", "").lower()
    is_normal_browser = 0 if ("curl" in user_agent or "python" in user_agent) else 1

    # Cria o array correspondente ao acesso atual
    dados_acesso_atual = np.array([hora_num, is_local_ip, is_normal_browser])
    
    # Converte de array 1D para matriz 2D esperado pelo scikit-learn
    dados_acesso_atual_2d = dados_acesso_atual.reshape(1, -1)
    
    # Faz a inferência de probabilidade
    probabilidades = ia_zero_trust.predict_proba(dados_acesso_atual_2d)
    
    # Extrai o escore flutuante exato da classe de risco (linha 0, coluna 1)
    escore_risco_ia = float(probabilidades[0][1])
    
    return escore_risco_ia