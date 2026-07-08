from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

# Importaciones de tus módulos locales
from llm_engine import analyze_security_payload
from notifier import send_telegram_alert
from database import engine, get_db, SessionLocal # Importamos SessionLocal
import models
from models import Tenant # Importamos Tenant para el init

# 0. Crear las tablas y asegurar datos iniciales
models.Base.metadata.create_all(bind=engine)

# Bloque de inicialización del Tenant
db_init = SessionLocal()
if not db_init.query(Tenant).filter(Tenant.id == 1).first():
    db_init.add(Tenant(id=1, name="Tenant Inicial"))
    db_init.commit()
db_init.close()

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
    db: Session = Depends(get_db)
):
    analysis_result = analyze_security_payload(event.raw_payload)
    attack_type = analysis_result.get("attack_type", "Unknown")
    risk_level = analysis_result.get("risk_level", "NONE")
    action_taken = analysis_result.get("action_taken", "Logged")
    is_attack = analysis_result.get("is_attack", False)
    
    db_status = "Evento no guardado."
    try:
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
        db.commit()
        db.refresh(nuevo_evento)
        db_status = "Evento registrado exitosamente en PostgreSQL."
    except Exception as e:
        db.rollback()
        db_status = f"Error al guardar en BD: {e}"

    soar_status = "Tráfico analizado."
    if is_attack and risk_level in ["HIGH", "CRITICAL"]:
        telegram_sent = send_telegram_alert(
            attack_type=attack_type,
            risk_level=risk_level,
            source_ip=event.source_ip,
            action_taken=action_taken,
            tenant_id=tenant_id
        )
        soar_status = f"ACCION SOAR: Ataque mitigado ({action_taken}) y notificado." if telegram_sent else "Fallo en notificación."
    
    return {
        "tenant_id": tenant_id,
        "source_ip": event.source_ip,
        "ia_analysis": {"is_attack": is_attack, "attack_type": attack_type, "risk_level": risk_level, "action_taken": action_taken},
        "database_status": db_status,
        "soar_orchestration": soar_status
    }

@app.get("/api/v1/events")
async def get_security_events(
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_tenant_from_api_key)
):
    """Obtiene el historial de eventos de seguridad del tenant autenticado."""
    events = db.query(models.SecurityEvent).filter(models.SecurityEvent.tenant_id == tenant_id).all()
    return events