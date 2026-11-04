FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY simular.py .
COPY tests ./tests

# Nao executa como root dentro do conteiner (privilegio minimo)
RUN useradd -m zt && mkdir -p /app/saida && chown -R zt /app
USER zt

EXPOSE 8000
CMD ["uvicorn", "app.proxy:app", "--host", "0.0.0.0", "--port", "8000"]
