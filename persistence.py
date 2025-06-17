import logging
import subprocess
import time

log = logging.getLogger(__name__)

class PersistenceModule:
    def run(self):
        while True:
            try:
                log.info("Ejecutando pipeline completo...")
                subprocess.run(["python", "main.py", "--target-program", "Valve"], check=True)
            except Exception as e:
                log.error(f"Fallo: {e}. Reiniciando en 60s...")
                time.sleep(60)
