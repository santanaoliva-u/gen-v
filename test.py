#!/usr/bin/env python3
# test.py
"""
Archivo de prueba para depurar problemas en el proyecto CazaDivina Gen-VI.
Verifica el entorno, importaciones, herramientas externas y la conexión a la base de datos.
"""

import sys  # Para manejar el sistema (como sys.path)
import os  # Para trabajar con directorios
import logging  # Para registrar mensajes (logs)
import json  # Para formatear logs como JSON
import asyncio  # Para manejar tareas asíncronas
from datetime import datetime  # Para obtener la fecha y hora
from typing import List  # Para definir tipos de datos

# Importaciones locales
from modules.database import Database  # Clase para interactuar con la base de datos
from modules.tool_wrapper import is_tool_available  # Función para verificar herramientas

# Configuración de logging estructurado
class JsonFormatter(logging.Formatter):
    """Formatea los logs como JSON para que sean fáciles de leer y analizar."""
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

# Configura el logger
logging.basicConfig(
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler('output/test.log'),  # Guarda logs en output/test.log
        logging.StreamHandler(sys.stdout)  # Muestra logs en la consola
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
    """Verifica la importación de is_tool_available."""
    log.info("=== Verificando importación de modules.tool_wrapper ===")
    try:
        from modules.tool_wrapper import is_tool_available
        log.info("Importación de modules.tool_wrapper.is_tool_available exitosa")
        return is_tool_available
    except ImportError as e:
        log.error(f"Error al importar modules.tool_wrapper: {e}")
        sys.exit(1)
    except AttributeError as e:
        log.error(f"Error: modules.tool_wrapper no tiene is_tool_available: {e}")
        sys.exit(1)

def test_tools(is_tool_available):
    """Prueba si las herramientas requeridas están disponibles."""
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

async def test_database():
    """Verifica la conexión y funcionalidad básica de la base de datos."""
    log.info("=== Probando conexión a la base de datos ===")
    try:
        db = await Database()  # Usa await para instanciar Database
        # Ejecuta una consulta simple para verificar la conexión
        result = await db.fetch_one_async("SELECT name FROM sqlite_master WHERE type='table' AND name='programs'")
        log.info(f"Tabla 'programs' existe: {bool(result)}")
        await db.close_all()  # Cierra todas las conexiones
        log.info("Conexión a la base de datos exitosa")
    except Exception as e:
        log.error(f"Error con la base de datos: {e}")
        sys.exit(1)

async def main():
    """Función principal para ejecutar todas las pruebas."""
    log.info("=== Iniciando pruebas avanzadas ===")
    print_project_info()
    
    # Verificar importación de tool_wrapper
    is_tool_available = check_tool_wrapper_import()
    
    # Probar herramientas
    test_tools(is_tool_available)
    
    # Probar base de datos
    await test_database()
    
    log.info("=== Pruebas completadas ===")

if __name__ == "__main__":
    try:
        asyncio.run(main())  # Ejecuta la función asíncrona
    except KeyboardInterrupt:
        log.info("Pruebas interrumpidas por el usuario")
        sys.exit(0)
    except Exception as e:
        log.error(f"Error inesperado: {e}")
        sys.exit(1)
