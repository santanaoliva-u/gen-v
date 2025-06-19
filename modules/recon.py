# modules/recon.py
"""
Módulo de reconocimiento para el pipeline de CazaDivina.
Ejecuta herramientas de reconocimiento y almacena resultados en la base de datos.
"""

import logging
import json
import asyncio
from typing import List, Optional
from modules.tool_wrapper import run_tool
from modules.database import Database

log = logging.getLogger(__name__)

class JsonFormatter(logging.Formatter):
    """Formatea los logs como JSON para que sean fáciles de leer y analizar."""
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": record.created,
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "file": record.pathname,
            "line": record.lineno
        }
        return json.dumps(log_entry, ensure_ascii=False)

# Configura el logger para ReconModule
formatter = JsonFormatter()
for handler in log.handlers:
    handler.setFormatter(formatter)

class ReconModule:
    def __init__(self):
        self.db = None

    async def run(self, program_name: Optional[str]) -> List[dict]:
        log.info("Iniciando reconocimiento...")
        results = []
        if not program_name:
            log.error("No se proporcionó un programa objetivo.")
            return results

        try:
            # Ejecutar herramientas de reconocimiento
            assetfinder_output = run_tool(f"assetfinder --subs-only {program_name}")
            if assetfinder_output:
                for domain in assetfinder_output.splitlines():
                    if domain.strip():
                        results.append({
                            "program_name": program_name,
                            "asset": domain.strip(),
                            "vuln_type": "Recon",
                            "severity": 0.0,
                            "description": f"Subdominio encontrado: {domain}"
                        })

            # Validar resultados con httpx
            if results:
                domains = [r["asset"] for r in results]
                httpx_input = "\n".join(domains)
                httpx_output = run_tool("httpx -silent", input_data=httpx_input)
                if httpx_output:
                    live_domains = httpx_output.splitlines()
                    results = [r for r in results if r["asset"] in live_domains]

            # Guardar resultados en la base de datos
            self.db = await Database()
            for result in results:
                await self.db.insert_finding_async(
                    result["program_name"],
                    result["asset"],
                    "",
                    result["description"],
                    result["vuln_type"],
                    result["severity"]
                )

            log.info(f"Reconocimiento completado para {program_name}. Encontrados {len(results)} resultados.")
        except Exception as e:
            log.error(f"Error en reconocimiento: {e}", exc_info=True)
        finally:
            if self.db:
                await self.db.close_all()

        return results
