import os
import json
import requests
from dotenv import load_dotenv
import google.generativeai as genai

# 1. Cargar las contraseñas y configuración del archivo .env
load_dotenv()

LLM_MODE = os.getenv("LLM_MODE", "cloud").lower()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# 2. Configurar la API key globalmente
if LLM_MODE == "cloud" and GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

def analyze_security_payload(payload: str) -> dict:
    """
    Analiza el payload sospechoso usando IA.
    """
    prompt = f"""
    Actúa como un experto analizador de ciberseguridad.
    Analiza el siguiente payload y clasifícalo en formato JSON.
    Payload: "{payload}"
    
    Responde ÚNICAMENTE en JSON válido con esta estructura exacta:
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
            # EL GRAN CAMBIO: Usamos el modelo que descubrimos en el diagnóstico
            model = genai.GenerativeModel('gemini-2.5-flash')
            response = model.generate_content(prompt)
            
            # Limpiamos la respuesta eliminando bloques markdown si existen
            response_text = response.text.strip().replace("```json", "").replace("```", "")
            return json.loads(response_text)
            
        # --- MODO LOCAL (OLLAMA) ---
        elif LLM_MODE == "local":
            url = "http://localhost:11434/api/generate"
            data = {
                "model": "llama3",
                "prompt": prompt,
                "stream": False,
                "format": "json"
            }
            response = requests.post(url, json=data)
            return json.loads(response.json()["response"])

    except Exception as e:
        print(f"Error en LLM Engine: {e}")
        # Fail-Safe: Mantiene la seguridad aunque el modelo falle o la red falle
        return {
            "is_attack": True,
            "attack_type": "Unknown",
            "risk_level": "HIGH",
            "action_taken": "Blocked_by_FailSafe"
        }