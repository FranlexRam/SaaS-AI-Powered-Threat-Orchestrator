import os
import json
import requests
from dotenv import load_dotenv
import google.generativeai as genai

# 1. Cargar las contraseñas y configuración del archivo .env
load_dotenv()

LLM_MODE = os.getenv("LLM_MODE", "cloud").lower()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# 2. Configurar Gemini si estamos en modo "cloud"
if LLM_MODE == "cloud" and GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    # Usamos Flash porque es el más rápido para analizar miles de ataques por segundo
    model = genai.GenerativeModel('gemini-1.5-flash')

def analyze_security_payload(payload: str) -> dict:
    """
    Esta función recibe el código sospechoso del cliente y usa IA para clasificarlo.
    """
    
    # Este es el "Prompt System" - Las instrucciones maestras para tu IA
    prompt = f"""
    Actúa como un experto analizador de ciberseguridad (Threat Orchestrator).
    Analiza el siguiente payload interceptado y determina si es un ataque cibernético.
    
    Payload interceptado: "{payload}"
    
    Responde ÚNICAMENTE en formato JSON válido con esta estructura exacta:
    {{
        "is_attack": true o false,
        "attack_type": "SQLi, RCE, XSS, Directory Traversal, SSRF, Brute Force, DDoS, o None",
        "risk_level": "LOW, MEDIUM, HIGH, CRITICAL, o NONE",
        "action_taken": "Blocked, Logged, o Allowed"
    }}
    """

    try:
        # --- MODO NUBE (GEMINI) ---
        if LLM_MODE == "cloud":
            response = model.generate_content(prompt)
            # Limpiamos la respuesta por si Gemini añade texto extra (markdown)
            response_text = response.text.strip().replace("```json", "").replace("```", "")
            return json.loads(response_text)
            
        # --- MODO LOCAL / AVIÓN (OLLAMA) ---
        elif LLM_MODE == "local":
            # Ollama corre localmente en el puerto 11434 por defecto
            url = "http://localhost:11434/api/generate"
            data = {
                "model": "llama3", # Puedes cambiarlo a "phi3" si es el que bajaste
                "prompt": prompt,
                "stream": False,
                "format": "json" # Forzamos a Ollama a responder en JSON
            }
            response = requests.post(url, json=data)
            return json.loads(response.json()["response"])

    except Exception as e:
        # Si la IA falla o se cae el internet, bloqueamos por seguridad (Fail-Safe)
        print(f"Error en LLM Engine: {e}")
        return {
            "is_attack": True,
            "attack_type": "Unknown",
            "risk_level": "HIGH",
            "action_taken": "Blocked_by_FailSafe"
        }