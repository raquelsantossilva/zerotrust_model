FROM python:3.10-slim

WORKDIR /app

# Copia todos os arquivos do projeto para o container
COPY . /app

# Instala as dependências necessárias
RUN pip install --no-cache-dir fastapi uvicorn psycopg2-binary scikit-learn numpy

# Expõe a porta interna
EXPOSE 8000

# Executa o uvicorn apontando para o módulo dentro de camada_de_acesso
CMD ["uvicorn", "camada_de_acesso.proxy:link", "--host", "0.0.0.0", "--port", "8000"]
