import os
import requests
from dotenv import load_dotenv

load_dotenv()
print(f"DEBUG: Token cargado: {os.getenv('TELEGRAM_BOT_TOKEN')}")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

def send_telegram_alert(attack_type: str, risk_level: str, source_ip: str, action_taken: str, tenant_id: int):
    """
    Envía una notificación estructurada a Telegram cuando el SOAR detecta un riesgo alto o crítico.
    """
    # Si falta alguna credencial en el .env, el sistema no se cae, solo lo reporta en consola
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[⚠️ SOAR Error] No se pueden enviar alertas de Telegram. Faltan variables en el archivo .env")
        return False

    # Diseño del mensaje usando formato Markdown
    message = (
        f"🚨 *ALERTA DE SEGURIDAD PERIMETRAL*\n"
        f"-------------------------------------\n"
        f"🏢 *Tenant ID:* {tenant_id}\n"
        f"🛡️ *Sistema:* Threat Orchestrator\n"
        f"💥 *Ataque Detectado:* `{attack_type}`\n"
        f"📊 *Nivel de Riesgo:* `{risk_level}`\n"
        f"🌐 *IP de Origen:* `{source_ip}`\n"
        f"⚙️ *Acción SOAR:* **{action_taken}**\n"
        f"-------------------------------------\n"
        f"🔒 _Sakti Shield - Monitoreo Activo_"
    )

    # URL oficial de la API de Telegram para enviar mensajes en texto
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown" # Permite usar negritas y bloques de código en Telegram
    }

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"[🔥 SOAR] Notificación enviada a Telegram con éxito para el Tenant {tenant_id}.")
            return True
        else:
            print(f"[⚠️ SOAR Error] Telegram respondió con código {response.status_code}: {response.text}")
            return False
    except Exception as e:
        print(f"[⚠️ SOAR Error] No se pudo conectar con la API de Telegram: {e}")
        return False