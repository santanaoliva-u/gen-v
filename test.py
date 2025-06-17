#!/usr/bin/env python3
# test.py
"""
Archivo de prueba avanzado para depurar problemas en el proyecto CazaDivina Gen-VI.
Verifica importaciones, sys.path, herramientas externas y conexión a la base de datos.
"""

import sys
import os
import logging
import json
from datetime import datetime
from typing import List

# Configuración de logging estructurado
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.msg % record.args if record.args else record.msg,
            "file": record.pathname,
            "line": record.lineno
        }
        return json.dumps(log_entry)

logging.basicConfig(
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler('output/test.log'),  # Guardar logs en output/test.log
        logging.StreamHandler(sys.stdout)  # Mostrar en consola
    ]
)
formatter = JsonFormatter()
for handler in logging.getLogger().handlers:
    handler.setFormatter(formatter)
log = logging.getLogger(__name__)

def print_project_info():
    """Imprime información sobre el entorno y la estructura del proyecto."""
    log.info("=== Información del Proyecto ===")
    log.info(f"Directorio actual: {os.getcwd()}")
    log.info(f"Python version: {sys.version}")
    log.info(f"sys.path: {json.dumps(sys.path, indent=2)}")
    project_root = os.path.abspath(os.path.dirname(__file__))
    log.info(f"Directorio raíz del proyecto: {project_root}")
    if project_root not in sys.path:
        log.warning("El directorio raíz no está en sys.path, agregándolo...")
        sys.path.append(project_root)

def check_tool_wrapper_import():
    """Verifica la importación de utils.tool_wrapper.is_tool_available."""
    log.info("=== Verificando importación de utils.tool_wrapper ===")
    try:
        from utils.tool_wrapper import is_tool_available
        log.info("Importación de utils.tool_wrapper.is_tool_available exitosa")
        return is_tool_available
    except ImportError as e:
        log.error(f"Error al importar utils.tool_wrapper: {e}")
        sys.exit(1)
    except AttributeError as e:
        log.error(f"Error: utils.tool_wrapper no tiene is_tool_available: {e}")
        sys.exit(1)

def test_tools(is_tool_available):
    """Prueba la función is_tool_available con las herramientas requeridas."""
    log.info("=== Probando herramientas requeridas ===")
    required_tools = [
        'amass', 'subfinder', 'assetfinder', 'findomain', 'dnsx', 'httpx',
        'waybackurls', 'gau', 'katana', 'ffuf', 'gobuster', 'dirsearch', 'arjun'
    ]
    missing_tools = []
    for tool in required_tools:
        try:
            available = is_tool_available(tool)
            log.info(f"Herramienta {tool}: {'Disponible' if available else 'No disponible'}")
            if not available:
                missing_tools.append(tool)
        except Exception as e:
            log.error(f"Error probando herramienta {tool}: {e}")
            missing_tools.append(tool)
    
    if missing_tools:
        log.warning(f"Herramientas faltantes: {', '.join(missing_tools)}")
    else:
        log.info("Todas las herramientas están disponibles")

def test_database():
    """Verifica la conexión y funcionalidad básica de la base de datos."""
    log.info("=== Probando conexión a la base de datos ===")
    try:
        from database import Database
        db = Database()
        # Ejecutar una consulta simple para verificar la conexión
        result = db.fetch_one("SELECT name FROM sqlite_master WHERE type='table' AND name='programs'")
        log.info(f"Tabla 'programs' existe: {bool(result)}")
        db.close()
        log.info("Conexión a la base de datos exitosa")
    except Exception as e:
        log.error(f"Error con la base de datos: {e}")
        sys.exit(1)

def main():
    """Función principal para ejecutar todas las pruebas."""
    log.info("=== Iniciando pruebas avanzadas ===")
    print_project_info()
    
    # Verificar importación de tool_wrapper
    is_tool_available = check_tool_wrapper_import()
    
    # Probar herramientas
    test_tools(is_tool_available)
    
    # Probar base de datos
    test_database()
    
    log.info("=== Pruebas completadas ===")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Pruebas interrumpidas por el usuario")
        sys.exit(0)
    except Exception as e:
        log.error(f"Error inesperado: {e}")
        sys.exit(1)
