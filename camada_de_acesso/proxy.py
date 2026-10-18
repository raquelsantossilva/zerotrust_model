from datetime import datetime
from fastapi import FastAPI,HTTPException,Request

link = FastAPI()

def extraction_data():
    hora = datetime.now()
    return hora

def extract_headers(request: Request):
    client_ip = request.client.host if request.client else "desconhecido"
    
    # Obtém informações do navegador ou ferramenta que está a enviar o pedido
    user_agent = request.headers.get("user-agent", "desconhecido")
    
    return client_ip,user_agent
    

def chamar_ia(pilares):
    escore_simulado = 0.5
    return escore_simulado

@link.get("/verificar_acesso")
def score(request:Request):
    hora_atual = extraction_data()
    ip,user = extract_headers(request)
    pilares ={
        "hora":hora_atual,
        "ip": ip,
        "user":user
    }

    score_risco = chamar_ia(pilares)

    if score_risco >= 0.7:
        raise HTTPException(status_code=403,
                            detail=f"Acesso negado: Risco elevado detetado (Escore: {score_risco})")
    return("dados banco")
