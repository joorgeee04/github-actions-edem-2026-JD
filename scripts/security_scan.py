"""Simula un escaneo de seguridad buscando claves API expuestas."""
import re
import sys
from pathlib import Path

PATRONES = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    "Clave genérica": re.compile(
        r"(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        re.IGNORECASE,
    ),
}
EXTENSIONES = {".py", ".json", ".yaml", ".yml", ".txt", ".env"}


def escanear(raiz):
    hallazgos = []
    for fichero in Path(raiz).rglob("*"):
        if not fichero.is_file() or fichero.suffix not in EXTENSIONES:
            continue
        if ".git" in fichero.parts or fichero.name == Path(__file__).name:
            continue
        texto = fichero.read_text(errors="ignore")
        for nombre, patron in PATRONES.items():
            if patron.search(texto):
                hallazgos.append(f"{fichero}: posible {nombre}")
    return hallazgos


if __name__ == "__main__":
    raiz = sys.argv[1] if len(sys.argv) > 1 else "."
    resultado = escanear(raiz)
    for h in resultado:
        print(f"::error::{h}")
    if resultado:
        sys.exit(1)
    print("Escaneo completado: no se han encontrado claves expuestas.")
