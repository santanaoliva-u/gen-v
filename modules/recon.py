# modules/recon.py
# Este archivo define el módulo ReconModule, que realiza reconocimiento de dominios y URLs.

import logging  # Para registrar mensajes (logs)
import asyncio  # Para manejar tareas asíncronas
from typing import List, Dict, Any  # Para definir tipos de datos
from modules.tool_wrapper import run_tool, is_tool_available  # Importa funciones para ejecutar y verificar herramientas
from modules.database import Database  # Clase para interactuar con la base de datos
from modules.config import CONFIG  # Configuración del proyecto

# Configura el logger para este módulo
log = logging.getLogger(__name__)

class ReconModule:
    def __init__(self):
        """Inicializa el módulo de reconocimiento."""
        self.required_tools = [
            'amass', 'subfinder', 'assetfinder', 'findomain', 'dnsx', 'httpx',
            'waybackurls', 'gau', 'katana'
        ]

    async def run(self, data: Any) -> List[Dict]:
        """Ejecuta el reconocimiento para un programa dado."""
        log.info("Iniciando reconocimiento...")
        # Verifica que todas las herramientas estén disponibles
        missing_tools = [tool for tool in self.required_tools if not is_tool_available(tool)]
        if missing_tools:
            log.error(f"Herramientas faltantes para ReconModule: {', '.join(missing_tools)}")
            return []

        program_name = data if isinstance(data, str) else data.get('program_name', 'Unknown')
        results = []
        db = await Database()

        # Ejemplo: Usa assetfinder para encontrar subdominios
        try:
            cmd = ["assetfinder", "--subs-only", program_name]
            output = run_tool(cmd)
            subdomains = output.get('stdout', '').splitlines()
            for subdomain in subdomains:
                if subdomain:
                    results.append({"target": subdomain, "program_name": program_name})
                    await db.insert_finding_async(
                        program_name, subdomain, f"https://{subdomain}", "Subdominio encontrado", "Recon", 2.0
                    )
        except Exception as e:
            log.error(f"Error ejecutando assetfinder: {e}")

        # Ejemplo: Usa httpx para verificar subdominios activos
        try:
            cmd = ["httpx", "-silent", "-o", f"output/{program_name}/httpx.txt"]
            output = run_tool(cmd, input='\n'.join([r['target'] for r in results]))
            active_urls = output.get('stdout', '').splitlines()
            for url in active_urls:
                if url:
                    results.append({"target": url, "program_name": program_name, "url": url})
        except Exception as e:
            log.error(f"Error ejecutando httpx: {e}")

        await db.close_all()
        log.info(f"Reconocimiento completado para {program_name}. Encontrados {len(results)} resultados.")
        return results
