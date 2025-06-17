# utils/tool_wrapper.py
import subprocess
import logging

log = logging.getLogger(__name__)

def run_tool(command: list, output_file: str = None) -> str:
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
        output = process.stdout
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
        return output
    except FileNotFoundError:
        log.error(f"Comando no encontrado: {command[0]}. ¿Está instalado y en el PATH?")
    except subprocess.CalledProcessError as e:
        log.error(f"Error en '{' '.join(command)}'. Salida: {e.stderr.strip()}")
    except Exception as e:
        log.error(f"Error inesperado con '{' '.join(command)}': {e}")
    return ""
