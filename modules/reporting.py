# modules/reporting.py
# Este archivo genera reportes en formato Markdown para las vulnerabilidades encontradas.

import os  # Para trabajar con directorios y archivos
import logging  # Para registrar mensajes (logs)
from datetime import datetime  # Para obtener la fecha y hora actual
from modules.config import REPORTS_DIR  # Importa el directorio donde se guardan los reportes
from modules.database import Database  # Importa la clase Database para interactuar con la base de datos

# Configura el logger para este módulo
log = logging.getLogger(__name__)

# Define la clase ReportingModule, que genera reportes para los hallazgos
class ReportingModule:
    def __init__(self):
        # Crea el directorio para reportes si no existe
        # 'exist_ok=True' evita errores si el directorio ya está creado
        os.makedirs(REPORTS_DIR, exist_ok=True)

    # Método principal que procesa una lista de hallazgos y genera reportes
    async def run(self, data: list) -> list:
        # Registra que se están generando los reportes
        log.info("Generando reportes...")
        # Asegura que 'data' sea una lista, si no, usa una lista vacía
        findings = data if isinstance(data, list) else []
        # Crea una instancia de la base de datos
        db = await Database()
        # Genera un reporte para cada hallazgo
        for finding in findings:
            await self.generate_report(finding, db)
        # Cierra todas las conexiones a la base de datos
        await db.close_all()
        # Retorna los datos originales (sin modificar)
        return data

    # Método que genera un reporte en formato Markdown para un hallazgo específico
    async def generate_report(self, finding: dict, db: Database):
        """
        Crea un archivo Markdown con detalles de una vulnerabilidad.
        Args:
            finding: Diccionario con los detalles del hallazgo (como objetivo, descripción, etc.).
            db: Instancia de la base de datos para guardar información del reporte.
        """
        # Crea una plantilla de texto para el reporte usando los datos del hallazgo
        report_template = f"""
# Reporte de Vulnerabilidad: {finding.get('description', 'N/A')}

- **Objetivo:** {finding.get('target', 'N/A')}
- **Programa:** {finding.get('program_name', 'N/A')}
- **Puntuación de Riesgo:** {finding.get('risk_score', 'N/A')}
- **Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Descripción
{finding.get('description', 'N/A')}

## Pasos para Reproducir
_# TODO:_ Añadir PoC

## Impacto
_# TODO:_ Describir impacto.
"""
        # Define el nombre del archivo basado en el ID del hallazgo
        file_name = f"finding_{finding.get('id', 'unknown')}.txt"
        # Combina el directorio de reportes con el nombre del archivo
        file_path = os.path.join(REPORTS_DIR, file_name)
        # Escribe la plantilla en el archivo
        with open(file_path, 'w') as f:
            f.write(report_template)
        # Guarda información sobre el reporte en la base de datos
        await db.insert_report_async(
            finding.get('program_name', 'unknown'), 'Markdown', file_path
        )
