import logging
import re
import requests

log = logging.getLogger(__name__)

class ContentAnalysisModule:
    def run(self, endpoints):
        log.info("Analizando contenido sensible...")
        patterns = [r"API_KEY", r"password", r"token"]
        for endpoint in endpoints:
            try:
                response = requests.get(endpoint, timeout=5)
                for pattern in patterns:
                    if re.search(pattern, response.text):
                        log.warning(f"¡Dato sensible en {endpoint}!")
            except:
                pass
