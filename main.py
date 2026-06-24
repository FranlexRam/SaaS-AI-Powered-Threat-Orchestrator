from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from llm_engine import analyze_security_payload
from notifier import send_telegram_alert  # <--- IMPORTAMOS TU NUEVO MÓDULO DE ALERTAS

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
async def ingest_security_event(event: EventPayload, tenant_id: int = Depends(get_tenant_from_api_key)):
    
    # 1. Análisis inteligente del payload dinámico
    analysis_result = analyze_security_payload(event.raw_payload)
    
    attack_type = analysis_result.get("attack_type", "Unknown")
    risk_level = analysis_result.get("risk_level", "NONE")
    action_taken = analysis_result.get("action_taken", "Logged")
    is_attack = analysis_result.get("is_attack", False)
    
    soar_status = "Tráfico analizado."

    # 2. Orquestación Defensiva Activa (SOAR)
    # Filtro comercial: Solo reaccionar si es un ataque confirmado y de riesgo ALTO o CRÍTICO
    if is_attack and risk_level in ["HIGH", "CRITICAL"]:
        # Disparamos la notificación asíncrona hacia Telegram
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

    # 3. Respuesta estructurada lista para el Dashboard
    return {
        "tenant_id": tenant_id,
        "source_ip": event.source_ip,
        "ia_analysis": {
            "is_attack": is_attack,
            "attack_type": attack_type,
            "risk_level": risk_level,
            "action_taken": action_taken
        },
        "soar_orchestration": soar_status
    }