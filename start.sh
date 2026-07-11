#!/bin/bash
echo "🚀 Iniciando infraestructura Sakti Shield..."

# 1. Levantar contenedores
docker-compose up -d

# 2. Activar entorno y lanzar API
source venv/bin/activate
echo "✅ Backend levantado. Accediendo a http://127.0.0.1:8000"
uvicorn main:app --reload