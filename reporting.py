# modules/reporting.py
import os
from datetime import datetime
from config import REPORTS_DIR

class ReportingModule:
    def __init__(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def run(self, data):
        log.info("Generando reportes...")
        # Assuming data is a list of findings from PredictModule
        findings = data if isinstance(data, list) else []
        for finding in findings:
            self.generate_report(finding)
        return data

    def generate_report(self, finding: dict):
        report_template = f"""
# Reporte de Vulnerabilidad: {finding.get('description', 'N/A')}

- **Objetivo:** {finding.get('target', 'N/A')}
- **Programa:** {finding.get('program_name', 'N/A')}
- **Puntuación de Riesgo Calculada:** {finding.get('risk_score', 'N/A')}
- **Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Descripción
{finding.get('description', 'N/A')}

## Pasos para Reproducir
_# TODO:_ Añadir PoC (ej. comando cURL)

## Impacto
_# TODO:_ Describir el impacto potencial en el negocio.
"""
        file_name = f"finding_{finding.get('id', 'unknown')}.md"
        with open(os.path.join(REPORTS_DIR, file_name), 'w') as f:
            f.write(report_template)
