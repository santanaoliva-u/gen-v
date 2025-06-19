# modules/tool_wrapper.py
"""
Este archivo contiene funciones para ejecutar herramientas externas y verificar su disponibilidad.
Usado por módulos como ReconModule para interactuar con herramientas de línea de comandos.
"""

import subprocess  # Para ejecutar comandos en la terminal
import logging  # Para registrar mensajes (logs)
import os  # Para trabajar con directorios y archivos
import shutil  # Para buscar comandos en el PATH del sistema
import json  # Para formatear logs como JSON
from datetime import datetime  # Para generar marcas de tiempo

# Configuración de logging estructurado
class JsonFormatter(logging.Formatter):
    """Formatea los logs como JSON para que sean fáciles de leer y analizar."""
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "file": record.pathname,
            "line": record.lineno
        }
        return json.dumps(log_entry)

# Configura el logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('output/tool_wrapper.log')
file_handler.setFormatter(JsonFormatter())
log.addHandler(file_handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(JsonFormatter())
log.addHandler(console_handler)

def is_tool_available(tool_name: str) -> bool:
    """
    Verifica si una herramienta está instalada en el sistema.
    Args:
        tool_name: Nombre de la herramienta (por ejemplo, 'httpx').
    Returns:
        bool: True si la herramienta está disponible, False si no.
    """
    found = shutil.which(tool_name) is not None
    if not found:
        log.warning(f"Herramienta '{tool_name}' no encontrada en el PATH.")
    return found

def run_tool(command: list, output_file: str = None, input_data: str = None) -> dict:
    """
    Ejecuta un comando en la terminal y captura su salida.
    Args:
        command: Lista de strings que forman el comando (por ejemplo, ["httpx", "-silent"]).
        output_file: Ruta opcional donde guardar la salida del comando.
        input_data: Datos opcionales para pasar como entrada a través de stdin.
    Returns:
        dict: Diccionario con el código de retorno, stdout y stderr.
    """
    try:
        log.info(f"Ejecutando: {' '.join(command)}")
        process = subprocess.run(
            command,
            check=True,  # Lanza un error si el comando falla
            capture_output=True,  # Captura la salida y los errores
            text=True,  # Devuelve la salida como texto
            encoding='utf-8',  # Usa codificación UTF-8
            errors='ignore',  # Ignora errores de codificación
            input=input_data  # Pasa datos a stdin si se proporcionan
        )
        result = {
            "returncode": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr
        }
        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(process.stdout)
        return result
    except FileNotFoundError:
        log.error(f"Comando no encontrado: {command[0]}")
        return {"returncode": 1, "stdout": "", "stderr": f"Comando no encontrado: {command[0]}"}
    except subprocess.CalledProcessError as e:
        log.error(f"Error en '{' '.join(command)}': {e.stderr.strip()}")
        return {"returncode": e.returncode, "stdout": e.stdout, "stderr": e.stderr}
    except Exception as e:
        log.error(f"Error inesperado con '{' '.join(command)}': {e}")
        return {"returncode": 1, "stdout": "", "stderr": str(e)}
