# utils/tool_wrapper.py
import subprocess
import logging
import os
import shutil

log = logging.getLogger(__name__)

def is_tool_available(tool_name: str) -> bool:
    """
    Verifica si una herramienta está instalada.
    Args:
        tool_name: Nombre de la herramienta a verificar.
    Returns:
        bool: True si la herramienta está disponible, False si no.
    """
    found = shutil.which(tool_name) is not None
    if not found:
        log.warning(f"Herramienta '{tool_name}' no encontrada en el PATH.")
    return found

def run_tool(command: list, output_file: str = None) -> dict:
    """
    Ejecuta un comando en la terminal y captura su salida.
    Args:
        command: Lista de strings que forman el comando.
        output_file: Ruta opcional donde guardar la salida.
    Returns:
        dict: Diccionario con el código de retorno, stdout y stderr.
    """
    try:
        log.info(f"Ejecutando: {' '.join(command)}")
        process = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        result = {
            "returncode": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr
        }
        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(process.stdout)
        return result
    except FileNotFoundError:
        log.error(f"Comando no encontrado: {command[0]}")
        return {"returncode": 1, "stdout": "", "stderr": "Comando no encontrado"}
    except subprocess.CalledProcessError as e:
        log.error(f"Error en '{' '.join(command)}': {e.stderr.strip()}")
        return {"returncode": e.returncode, "stdout": e.stdout, "stderr": e.stderr}
    except Exception as e:
        log.error(f"Error inesperado con '{' '.join(command)}': {e}")
        return {"returncode": 1, "stdout": "", "stderr": str(e)}
