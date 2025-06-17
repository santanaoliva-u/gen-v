# modules/execution.py
import logging
import requests
import re
from utils.tool_wrapper import run_tool
from database import Database
from config import CONFIG

log = logging.getLogger(__name__)

class ExecutionModule:
    def __init__(self):
        self.db = Database()
        self.program_name = None

    def run(self, data: tuple) -> tuple:
        """
        Run vulnerability analysis on live hosts and endpoints.
        Expects data as (live_hosts, endpoints) from ReconModule.
        Returns (live_hosts, endpoints) for downstream modules.
        """
        live_hosts, endpoints = data if isinstance(data, tuple) else ([], [])
        self.program_name = "Valve"  # Set dynamically or pass via config
        log.info(f"Iniciando Fase 2: Análisis de Vulnerabilidades en {len(live_hosts)} hosts y {len(endpoints)} endpoints...")
        self.update_cves()  # Update CVEs before scanning
        for host in live_hosts:
            self.run_nuclei(host)
            self.run_dalfox(host, endpoints)
        return live_hosts, endpoints

    def update_cves(self):
        """Fetch and update CVE data from NVD API."""
        log.info("Actualizando base de datos de CVEs...")
        url = CONFIG["cve"]["api_url"]
        params = {"resultsPerPage": 100, "startIndex": 0}
        try:
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                cves = response.json()["result"]["CVE_Items"]
                for cve in cves:
                    cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                    description = cve["cve"]["description"]["description_data"][0]["value"]
                    severity = cve["impact"].get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "UNKNOWN")
                    affected = str(cve["configurations"]["nodes"])
                    last_updated = cve["lastModifiedDate"]
                    self.db.execute_query(
                        "INSERT OR REPLACE INTO cves (id, description, severity, affected_products, last_updated) VALUES (?, ?, ?, ?, ?)",
                        (cve_id, description, severity, affected, last_updated)
                    )
            else:
                log.error(f"Error al actualizar CVEs: HTTP {response.status_code}")
        except Exception as e:
            log.error(f"Error al actualizar CVEs: {e}")

    def run_nuclei(self, host: str):
        """Scan host with Nuclei for vulnerabilities."""
        log.info(f"Escaneando {host} con Nuclei...")
        command = ["nuclei", "-u", host, "-silent", "-t", "cves,xss,rce"]  # Focus on critical templates
        results = run_tool(command)
        if results:
            self._process_results(host, results)

    def run_dalfox(self, host: str, endpoints: list):
        """Scan host and endpoints for XSS with Dalfox."""
        log.info(f"Buscando XSS en {host} con Dalfox...")
        # Scan the host itself
        command = ["dalfox", "url", host, "--silence"]
        results = run_tool(command)
        if results:
            self._process_results(host, results)
        # Scan endpoints if available
        for endpoint in endpoints:
            if host in endpoint:  # Only scan endpoints related to this host
                command = ["dalfox", "url", endpoint, "--silence"]
                results = run_tool(command)
                if results:
                    self._process_results(host, results)

    def _process_results(self, host: str, results: str):
        """Process scan results and store findings in the database."""
        for line in results.splitlines():
            description = line.strip()
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", description)
            cve_id = cve_match.group(0) if cve_match else None
            self.db.execute_query(
                "INSERT INTO findings (program_name, target, description, cve, timestamp) VALUES (?, ?, ?, ?, datetime('now'))",
                (self.program_name, host, description, cve_id)
            )
            finding_id = self.db.cursor.lastrowid
            if cve_id:
                self.db.execute_query(
                    "INSERT INTO finding_cves (finding_id, cve_id) VALUES (?, ?)",
                    (finding_id, cve_id)  # Fixed: Properly closed parenthesis
                )
