# modules/execution.py
# Este archivo define el módulo de ejecución, que prueba URLs contra vulnerabilidades como XSS, SQLi, CVEs y fuzzing.

import logging  # Para registrar mensajes (logs) sobre lo que hace el programa
import requests  # Para hacer solicitudes HTTP (como descargar datos de una API)
import re  # Para buscar patrones en texto (como IDs de CVEs)
import subprocess  # Para ejecutar comandos en la terminal
from modules.tool_wrapper import run_tool  # Importa la función para ejecutar herramientas externas
from modules.database import Database  # Importa la clase Database para guardar datos
from modules.config import CONFIG  # Importa la configuración del proyecto

# Configura el logger para este módulo (registra mensajes con el nombre del módulo)
log = logging.getLogger(__name__)

# Define la clase ExecutionModule, que contiene la lógica para ejecutar pruebas de seguridad
class ExecutionModule:
    # Método principal que ejecuta las pruebas. Es asíncrono (usa 'async' para manejar tareas simultáneamente)
    async def run(self, data: list) -> list:
        # Si 'data' no es una lista, usa una lista vacía. Esto evita errores si los datos no son válidos
        findings = data if isinstance(data, list) else []
        if not findings:
            # Si no hay datos para procesar, registra un mensaje y retorna una lista vacía
            log.info("No se recibieron datos para ejecutar.")
            return []
        
        # Crea una instancia de la base de datos para guardar resultados
        db = await Database()
        # Obtiene el nombre del programa (por ejemplo, 'Valve') desde los datos o usa 'Valve' por defecto
        program = findings[0].get('program_name', 'Valve') if findings else 'Valve'
        # Define el directorio donde se guardarán los resultados
        out_dir = f"output/{program}"
        # Crea el directorio si no existe, usando un comando de terminal
        subprocess.run(f"mkdir -p {out_dir}", shell=True, check=True)
        
        # Actualiza la base de datos con información sobre CVEs (vulnerabilidades conocidas)
        await self.update_cves(db, program)
        
        # Lista para almacenar los resultados de las pruebas
        results = []
        # Itera sobre cada elemento en 'findings' (datos de entrada)
        for finding in findings:
            # Obtiene el objetivo (como un dominio) y la URL a probar
            target = finding.get('target')
            url = finding.get('url', f"https://{target}")
            # Calcula la probabilidad de riesgo (escalada de 0 a 10)
            prob = finding.get('risk_score', 5.0) / 10
            
            # Prueba 1: XSS (Cross-Site Scripting) con la herramienta 'dalfox'
            cmd = ["dalfox", "url", url, "--waf-bypass", "-o", f"{out_dir}/xss_{hash(url)}.txt"]
            try:
                # Ejecuta el comando y captura la salida
                output = run_tool(cmd)
                # Si la salida contiene "Found", se detectó un posible XSS
                if "Found" in output.get('stdout', ''):
                    # Guarda el resultado en la lista
                    results.append({"type": "XSS", "url": url, "details": output['stdout']})
                    # Guarda el hallazgo en la base de datos
                    await db.insert_finding_async(program, target, url, output['stdout'], "XSS Reflejado", prob * 10)
            except subprocess.CalledProcessError as e:
                # Si hay un error, registra el mensaje
                log.error(f"Error en dalfox: {e}")
            
            # Prueba 2: SQL Injection con la herramienta 'sqlmap'
            # Corrección: se eliminó la coma dentro de "--level=3" y se aseguró que las comillas estén correctas
            cmd = ["sqlmap", "-u", url, "--batch", "--level=3", "--risk=2", "--dbs", "-o", f"{out_dir}/sqli_{hash(url)}.txt"]
            try:
                output = run_tool(cmd)
                # Si la salida contiene "vulnerable", se detectó una posible inyección SQL
                if "vulnerable" in output.get('stdout', '').lower():
                    results.append({"type": "SQLi", "url": url, "details": output['stdout']})
                    await db.insert_finding_async(program, target, url, output['stdout'], "SQLi", prob * 10)
            except subprocess.CalledProcessError as e:
                log.error(f"Error en sqlmap: {e}")
            
            # Prueba 3: CVEs con la herramienta 'nuclei'
            cmd = ["nuclei", "-u", url, "-t", "cves/", "-o", f"{out_dir}/nuclei_{hash(url)}.txt"]
            try:
                output = run_tool(cmd)
                # Si la salida contiene "cve", se detectó una vulnerabilidad conocida
                if "cve" in output.get('stdout', '').lower():
                    # Busca un ID de CVE (formato: CVE-YYYY-XXXX)
                    cve_id = re.search(r"CVE-\d{4}-\d{4,7}", output['stdout'])
                    results.append({"type": "CVE", "url": url, "details": output['stdout']})
                    # Guarda el hallazgo con el ID del CVE si se encontró
                    await db.insert_finding_async(program, target, url, output['stdout'], "CVE", prob * 10, cve_id.group(0) if cve_id else None)
            except subprocess.CalledProcessError as e:
                log.error(f"Error en nuclei: {e}")
            
            # Prueba 4: Fuzzing con la herramienta 'ffuf'
            cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", "modules/xss_payloads.txt", "-o", f"{out_dir}/fuzz_{hash(url)}.txt"]
            try:
                output = run_tool(cmd)
                # Si la salida contiene "200" (código HTTP de éxito), se encontró algo interesante
                if "200" in output.get('stdout', ''):
                    results.append({"type": "Fuzz", "url": url, "details": output['stdout']})
                    await db.insert_finding_async(program, target, url, output['stdout'], "Fuzz", prob * 10)
            except subprocess.CalledProcessError as e:
                log.error(f"Error en ffuf: {e}")
        
        # Cierra todas las conexiones a la base de datos
        await db.close_all()
        # Retorna los resultados encontrados
        return results

    # Método para actualizar información sobre CVEs desde una API
    async def update_cves(self, db: Database, program: str):
        log.info("Actualizando CVEs...")
        # Obtiene la URL de la API de CVEs desde la configuración
        url = CONFIG.get("cve", {}).get("api_url")
        # Define parámetros para la solicitud (limita a 10 resultados)
        params = {"resultsPerPage": 10, "startIndex": 0}
        try:
            # Hace una solicitud HTTP a la API
            response = requests.get(url, params=params, timeout=5)
            if response.status_code == 200:
                # Si la solicitud es exitosa, extrae los CVEs del JSON
                cves = response.json().get("result", {}).get("CVE_Items", [])
                for cve in cves:
                    # Extrae el ID y la descripción del CVE
                    cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                    description = cve["cve"]["description"]["description_data"][0]["value"]
                    # Guarda el CVE en la base de datos
                    await db.insert_finding_async(
                        program, "NVD", "", f"CVE {cve_id}: {description}", "CVE", 0.0, cve_id
                    )
            else:
                # Si la solicitud falla, registra el error
                log.error(f"Error al actualizar CVEs: HTTP {response.status_code}")
        except Exception as e:
            # Si ocurre cualquier otro error, registra el mensaje
            log.error(f"Error al actualizar CVEs: {e}")
