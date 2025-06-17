# monitor.py
import os
import time
import logging
import subprocess
from database import Database

log = logging.getLogger(__name__)

class SystemMonitor:
    def __init__(self):
        self.db = Database()
        logging.basicConfig(filename="output/system.log", level=logging.INFO)

    def check_health(self):
        log.info("Verificando salud del sistema...")
        with open("output/system.log", "r") as f:
            errors = [line for line in f if "ERROR" in line]
        if errors:
            log.warning(f"Se detectaron {len(errors)} errores. Intentando reparar...")
            self.repair()

    def repair(self):
        # Reintentar procesos fallidos
        failed_findings = self.db.fetch_all("SELECT * FROM findings WHERE status = 'NEW' LIMIT 5")
        for finding in failed_findings:
            log.info(f"Reprocesando hallazgo ID {finding['id']}...")
            # TODO: Reejecutar el módulo correspondiente

    def update_tools(self):
        log.info("Actualizando herramientas externas...")
        subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"], check=False)

    def run(self):
        while True:
            self.check_health()
            self.update_tools()
            time.sleep(300)  # Revisar cada 5 minutos

if __name__ == "__main__":
    monitor = SystemMonitor()
    monitor.run()
