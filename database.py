import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

# Obtenemos la URL de conexión desde el entorno seguro (.env)
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# Creamos el motor de conexión a PostgreSQL
# pool_size y max_overflow ayudan a manejar múltiples conexiones concurrentes (ideal para SaaS)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    pool_size=10, 
    max_overflow=20
)

# SessionLocal será la fábrica de sesiones para nuestras consultas SQL
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base es la clase de la que heredan los modelos que tienes en el Canvas
Base = declarative_base()

def get_db():
    """
    Dependencia de FastAPI para abrir una sesión de base de datos por cada petición
    y cerrarla de forma segura al terminar, evitando fugas de memoria.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()