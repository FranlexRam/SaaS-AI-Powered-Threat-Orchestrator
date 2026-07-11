from fastapi import FastAPI, Depends, HTTPException, Security, WebSocket, WebSocketDisconnect
from fastapi.security.api_key import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List
from collections import defaultdict, deque
import time

# Importaciones de tus módulos locales
from llm_engine import analyze_security_payload
from notifier import send_telegram_alert
from database import engine, get_db, SessionLocal 
import models
from models import Tenant

# 1. Inicialización de la App
app = FastAPI(title="Sakti Shield Threat Orchestrator")

# Montar la carpeta estática para servir el Dashboard
app.mount("/static", StaticFiles(directory="static"), name="static")

# 2. Gestión de WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

# 3. Motor de Correlación (NUEVO)
class EventCorrelator:
    def __init__(self, limit=3, window_seconds=60):
        self.history = defaultdict(deque)
        self.limit = limit
        self.window = window_seconds

    def check_threat(self, source_ip: str):
        now = time.time()
        # Limpiar eventos fuera de ventana
        while self.history[source_ip] and self.history[source_ip][0] < now - self.window:
            self.history[source_ip].popleft()
        self.history[source_ip].append(now)
        return len(self.history[source_ip]) >= self.limit

correlator = EventCorrelator(limit=3, window_seconds=60)

# 4. Crear tablas e inicializar Tenant
models.Base.metadata.create_all(bind=engine)
db_init = SessionLocal()
if not db_init.query(Tenant).filter(Tenant.id == 1).first():
    db_init.add(Tenant(id=1, name="Tenant Inicial"))
    db_init.commit()
db_init.close()

# 5. Seguridad y Modelos
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

# 6. Endpoints
@app.websocket("/ws/security-events/{tenant_id}")
async def websocket_endpoint(websocket: WebSocket, tenant_id: int):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

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
    
    # --- LÓGICA DE CORRELACIÓN ---
    if correlator.check_threat(event.source_ip):
        is_attack = True
        risk_level = "CRITICAL"
        attack_type = f"PATRON_PERSISTENTE: {attack_type}"
        action_taken = "BLOQUEO_TEMPORAL_IP"
    
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
    
    # --- ORQUESTACION SOAR Y DIAGNOSTICO ---
    soar_status = "Tráfico analizado."
    if is_attack and risk_level in ["HIGH", "CRITICAL"]:
        telegram_sent = send_telegram_alert(
            attack_type=attack_type,
            risk_level=risk_level,
            source_ip=event.source_ip,
            action_taken=action_taken,
            tenant_id=tenant_id
        )
        print(f"DEBUG: Intento de notificación Telegram. ¿Enviado? {telegram_sent}")
        soar_status = "Notificado a Telegram" if telegram_sent else "Fallo en notificación Telegram"

    # --- BROADCAST PARA EL DASHBOARD ---
    await manager.broadcast({
        "tenant_id": tenant_id,
        "attack_type": attack_type,
        "risk_level": risk_level,
        "source_ip": event.source_ip,
        "soar_status": soar_status
    })

    return {"status": "success", "ia_analysis": analysis_result, "soar_status": soar_status}

@app.get("/api/v1/events")
async def get_security_events(
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_tenant_from_api_key)
):
    return db.query(models.SecurityEvent).filter(models.SecurityEvent.tenant_id == tenant_id).all()