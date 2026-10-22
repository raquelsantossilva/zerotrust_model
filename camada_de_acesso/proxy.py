from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from bancodedados.conection import conection_postgres  
from ia_avalicao_risco.ia import regression_model_zero_trust
link = FastAPI()

def buscar_dados_no_banco():
    conexao = conection_postgres
    try:
        cursor = conexao.cursor()
        cursor.execute("SELECT * FROM redes;")
        dados = cursor.fetchall()
        cursor.close()
        return dados
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro no banco: {str(e)}")
    finally:
        conexao.close()

def extraction_data():
    return datetime.now()

def extract_headers(request: Request):
    client_ip = request.client.host if request.client else "desconhecido"
    user_agent = request.headers.get("user-agent", "desconhecido")
    return client_ip, user_agent

def chamar_ia(pilares):
    score =regression_model_zero_trust(pilares)
    return score

@link.get("/verificar_acesso")
def test_score(request: Request):
    hora_atual = extraction_data()
    ip, user = extract_headers(request)
    
    pilares = {
        "hora": hora_atual,
        "ip": ip,
        "user": user
    }

    print("--- DADOS RECEBIDOS DA REQUISIÇÃO ---")
    print(f"IP do cliente: {ip}")
    print(f"User-Agent: {user}")
    print(f"Pilares montados: {pilares}")
    print("---------------------------------------")

    score_risco = chamar_ia(pilares)

    if score_risco >= 0.7:
        raise HTTPException(
            status_code=403,
            detail=f"Acesso negado: Risco elevado detectado (Escore: {score_risco})"
        )
    
    dados_tabela = buscar_dados_no_banco()
    return {"status": "Acesso Autorizado", "dados": dados_tabela}
