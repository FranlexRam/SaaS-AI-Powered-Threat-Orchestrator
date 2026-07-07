from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

# Importaciones de tus módulos locales
from llm_engine import analyze_security_payload
from notifier import send_telegram_alert
from database import engine, get_db
import models

# 0. Crear las tablas en la base de datos automáticamente al arrancar
# Esto garantiza que la estructura de PostgreSQL esté siempre sincronizada
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Sakti Shield Threat Orchestrator")

api_key_header = APIKeyHeader(name="X-Sakti-API-Key", auto_error=False)

class EventPayload(BaseModel):
    source_ip: str
    raw_payload: str

async def get_tenant_from_api_key(api_key_header: str = Security(api_key_header)):
    if not api_key_header:
        raise HTTPException(status_code=403, detail="API Key missing")
    if api_key_header == "mi_api_key_secreta_123":
        return 1 
    raise HTTPException(status_code=403, detail="Invalid API Key")

@app.post("/api/v1/ingest")
async def ingest_security_event(
    event: EventPayload, 
    tenant_id: int = Depends(get_tenant_from_api_key),
    db: Session = Depends(get_db)  # <--- Inyectamos la conexión a PostgreSQL por cada petición
):
    
    # 1. Análisis inteligente del payload dinámico
    analysis_result = analyze_security_payload(event.raw_payload)
    
    attack_type = analysis_result.get("attack_type", "Unknown")
    risk_level = analysis_result.get("risk_level", "NONE")
    action_taken = analysis_result.get("action_taken", "Logged")
    is_attack = analysis_result.get("is_attack", False)
    
    # 2. Guardar el evento en PostgreSQL (Memoria a largo plazo)
    db_status = "Evento no guardado."
    try:
        # Instanciamos el registro basado en tu modelo (asumiendo que se llama SecurityEvent)
        nuevo_evento = models.SecurityEvent(
            tenant_id=tenant_id,
            source_ip=event.source_ip,
            payload=event.raw_payload,
            is_attack=is_attack,
            attack_type=attack_type,
            risk_level=risk_level,
            action_taken=action_taken,
            timestamp=datetime.utcnow()
        )
        db.add(nuevo_evento)
        db.commit()              # Guardamos los cambios
        db.refresh(nuevo_evento) # Refrescamos para obtener el ID asignado por la BD
        db_status = "Evento registrado exitosamente en PostgreSQL."
    except Exception as e:
        db.rollback() # Si algo falla, deshacemos la transacción para no corromper la BD
        db_status = f"Error al guardar en BD: {e}"

    # 3. Orquestación Defensiva Activa (SOAR)
    soar_status = "Tráfico analizado."
    
    if is_attack and risk_level in ["HIGH", "CRITICAL"]:
        telegram_sent = send_telegram_alert(
            attack_type=attack_type,
            risk_level=risk_level,
            source_ip=event.source_ip,
            action_taken=action_taken,
            tenant_id=tenant_id
        )
        if telegram_sent:
            soar_status = f"ACCION SOAR: Ataque mitigado ({action_taken}) y administrador notificado via Telegram."
        else:
            soar_status = f"ACCION SOAR: Ataque mitigado ({action_taken}), pero falló el canal de notificación."
    else:
        soar_status = f"Monitoreo pasivo: Evento registrado con riesgo {risk_level}. No requiere activación de alertas SOAR."

    # 4. Respuesta estructurada lista para el Dashboard
    return {
        "tenant_id": tenant_id,
        "source_ip": event.source_ip,
        "ia_analysis": {
            "is_attack": is_attack,
            "attack_type": attack_type,
            "risk_level": risk_level,
            "action_taken": action_taken
        },
        "database_status": db_status,
        "soar_orchestration": soar_status
    }