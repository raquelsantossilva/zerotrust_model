import psycopg2

conection_postgres = psycopg2.connect(
        host="db",
        database="ufc_data",
        user="postgres",
        password="minha_senha",
        port="5432"
    )

with conection_postgres.cursor() as cursor:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS redes(
            id SERIAL PRIMARY KEY,
            professor VARCHAR(50) NOT NULL,
            numero_alunos INT
        );""")
    cursor.execute("""
        INSERT INTO redes(professor,numero_alunos) VALUES('pitagoras',30)
    """)
    conection_postgres.commit()