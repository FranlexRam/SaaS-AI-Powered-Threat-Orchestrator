import os
from dotenv import load_dotenv
import google.generativeai as genai

# Cargar la API Key
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    print("❌ ERROR: No se encontró la API Key en el archivo .env")
else:
    genai.configure(api_key=API_KEY)
    print("\n🔍 --- PREGUNTANDO A GOOGLE QUÉ MODELOS TIENES HABILITADOS --- 🔍\n")
    try:
        modelos = genai.list_models()
        for m in modelos:
            # Imprimimos todos los nombres sin filtrar para evitar errores
            print(f"✅ Modelo permitido: {m.name}")
        print("\n------------------------------------------------------------\n")
    except Exception as e:
        print(f"❌ Error de conexión con Google: {e}")