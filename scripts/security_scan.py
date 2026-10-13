"""Simula un escaneo de seguridad buscando claves API expuestas."""
import re
import sys
from pathlib import Path

# Patrón de una clave de AWS (AKIA + 16 caracteres) o texto tipo api_key = "..."
PATRON = re.compile(r"AKIA[0-9A-Z]{16}|api_key\s*=\s*\S+", re.IGNORECASE)

encontradas = 0
for fichero in Path(".").rglob("*.json"):
    if PATRON.search(fichero.read_text()):
        print(f"Posible clave expuesta en {fichero}")
        encontradas += 1

if encontradas:
    sys.exit(1)  # un código distinto de 0 hace fallar el step
print("No se han encontrado claves expuestas")
