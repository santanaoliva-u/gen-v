#!/usr/bin/env python3
# main.py
# Este archivo es el punto de entrada principal para el pipeline de CazaDivina.
# Carga la configuración, inicializa módulos y ejecuta pruebas de seguridad.

import argparse  # Para manejar argumentos de la línea de comandos
import logging  # Para registrar mensajes (logs)
import logging.handlers  # Para rotar archivos de log
import yaml  # Para leer el archivo de configuración (config.yaml)
import importlib  # Para importar módulos dinámicamente
import sys  # Para manejar el sistema (como salir del programa)
import time  # Para medir el tiempo de ejecución
import json  # Para formatear logs como JSON
import psutil  # Para obtener información del sistema (como número de CPUs)
import asyncio  # Para manejar tareas asíncronas
import requests  # Para enviar notificaciones a Discord
from concurrent.futures import ThreadPoolExecutor, as_completed  # Para ejecutar tareas en paralelo
from datetime import datetime  # Para obtener la fecha y hora
from typing import Dict, List, Optional, Any  # Para definir tipos de datos

# Importaciones locales
from modules.database import Database  # Clase para interactuar con la base de datos
from modules.tool_wrapper import run_tool, is_tool_available  # Funciones para ejecutar herramientas y verificar su disponibilidad

# Configuración de Logging
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
log.setLevel(logging.INFO)
# Guarda logs en un archivo que rota cuando alcanza 10MB
file_handler = logging.handlers.RotatingFileHandler(
    filename='output/system.log', maxBytes=10*1024*1024, backupCount=5
)
file_handler.setFormatter(JsonFormatter())
log.addHandler(file_handler)
# Muestra logs en la consola
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(JsonFormatter())
log.addHandler(console_handler)

# Clase Orchestrator: Coordina la ejecución de módulos
class Orchestrator:
    def __init__(self, config_file: str = "config.yaml"):
        """Inicializa el orquestador con un archivo de configuración."""
        self.db = None  # Conexión a la base de datos (se inicializa después)
        self.modules: List[Any] = []  # Lista de módulos cargados
        self.config: Dict[str, Any] = {}  # Configuración cargada desde config.yaml
        self.scope: Dict[str, Any] = {}  # Alcance del programa (dominios, etc.)
        self.module_dependencies: Dict[str, List[str]] = {}  # Dependencias entre módulos
        self.max_workers = min(10, psutil.cpu_count(logical=True) * 2 or 1)  # Número de hilos para ejecutar tareas
        self.discord_webhook: Optional[str] = None  # URL para notificaciones de Discord
        self._load_config(config_file)  # Carga la configuración

    async def initialize(self):
        """Inicializa la base de datos y valida el entorno."""
        self.db = await Database()  # Crea una instancia de la base de datos
        await self.validate_environment()  # Verifica que las herramientas estén instaladas

    def _load_config(self, config_file: str):
        """Carga y valida el archivo de configuración (config.yaml)."""
        try:
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f)  # Lee el archivo YAML
            self._validate_config_schema()  # Valida que tenga las claves necesarias
            self.module_dependencies = self.config.get('module_dependencies', {})
            # Mapeo de nombres de módulos a archivos en la carpeta modules
            module_map = {
                'IntelModule': 'intel',
                'ReconModule': 'recon',
                'ExecutionModule': 'execution',
                'PredictModule': 'predict',
                'StealthModule': 'stealth',
                'ReportingModule': 'reporting',
                'LearningModule': 'learning'
            }
            for module_name in self.config.get('modules', []):
                module_file = module_map.get(module_name)
                if module_file:
                    try:
                        # Importa el módulo dinámicamente
                        module = importlib.import_module(f"modules.{module_file}")
                        module_instance = getattr(module, module_name)()  # Crea una instancia del módulo
                        # Si el método run es asíncrono, lo envuelve para hacerlo síncrono
                        if asyncio.iscoroutinefunction(module_instance.run):
                            module_instance.run = self._wrap_async_run(module_instance.run)
                        self.modules.append(module_instance)
                        log.info(f"Módulo '{module_name}' cargado exitosamente.")
                    except ImportError as ie:
                        log.error(f"Error al importar '{module_name}': {ie}")
                        sys.exit(1)
                    except AttributeError as ae:
                        log.error(f"Error al encontrar '{module_name}' en '{module_file}.py': {ae}")
                        sys.exit(1)
                else:
                    log.warning(f"Módulo desconocido: {module_name}")
            self.scope = self.config.get('scope', {})
            self.discord_webhook = self.config.get('discord_webhook')
        except FileNotFoundError:
            log.error(f"Archivo de configuración '{config_file}' no encontrado.")
            sys.exit(1)
        except yaml.YAMLError as ye:
            log.error(f"Error de formato YAML en '{config_file}': {ye}")
            sys.exit(1)
        except Exception as e:
            log.error(f"Error al cargar configuración: {e}", exc_info=True)
            sys.exit(1)

    def _wrap_async_run(self, async_run):
        """Convierte un método asíncrono en síncrono para compatibilidad."""
        def sync_run(*args, **kwargs):
            return asyncio.run(async_run(*args, **kwargs))
        return sync_run

    def _validate_config_schema(self):
        """Verifica que el archivo config.yaml tenga las claves necesarias."""
        required_keys = ['modules', 'scope']
        for key in required_keys:
            if key not in self.config:
                log.error(f"Falta clave requerida en config.yaml: '{key}'.")
                sys.exit(1)
        if not self.config['scope'].get('include'):
            log.error("El scope debe incluir al menos un dominio en 'include'.")
            sys.exit(1)

    async def validate_environment(self):
        """Verifica que todas las herramientas necesarias estén instaladas."""
        log.info("Validando entorno...")
        required_tools = [
            'amass', 'subfinder', 'assetfinder', 'findomain', 'dnsx', 'httpx',
            'waybackurls', 'gau', 'katana', 'dalfox', 'sqlmap', 'nuclei', 'ffuf', 'wafw00f'
        ]
        missing_tools = [tool for tool in required_tools if not is_tool_available(tool)]
        if missing_tools:
            log.error(f"Herramientas faltantes: {', '.join(missing_tools)}")
            sys.exit(1)
        log.info("Todas las herramientas están disponibles.")

    async def run_full_pipeline(self, program_name: str, selected_modules: Optional[List[str]] = None):
        """Ejecuta todos los módulos en el pipeline para un programa dado."""
        start_time = time.time()
        log.info(f"Iniciando pipeline para: '{program_name}'")
        # No insertar hallazgos para eventos del pipeline
        # run_id = await self.db.insert_finding_async(
        #     program_name, program_name, "", f"Inicio pipeline {program_name}", "Pipeline", 0.0
        # ) or 0
        data: Any = program_name
        executed_module_names = set()
        modules_to_run = [
            m for m in self.modules if not selected_modules or m.__class__.__name__ in selected_modules]
        if not modules_to_run:
            log.warning("No hay módulos para ejecutar.")
            # No insertar hallazgos para eventos del pipeline
            # await self.db.insert_finding_async(
            #     program_name, program_name, "", "Sin módulos ejecutados", "Pipeline", 0.0
            # )
            return
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while len(executed_module_names) < len(modules_to_run):
                futures = {}
                for module in modules_to_run:
                    module_name = module.__class__.__name__
                    if module_name in executed_module_names:
                        continue
                    dependencies = self.module_dependencies.get(module_name, [])
                    if all(dep in executed_module_names for dep in dependencies):
                        future = executor.submit(self._run_module, module, data, program_name)
                        futures[future] = module_name
                if not futures:
                    log.error("No hay módulos listos para ejecutar. Posible ciclo de dependencias.")
                    break
                for future in as_completed(futures):
                    module_name = futures[future]
                    try:
                        result = future.result()
                        if result is not None:
                            data = result
                        log.info(f"Módulo '{module_name}' completado.")
                        executed_module_names.add(module_name)
                    except Exception as e:
                        log.error(f"Error en '{module_name}': {e}", exc_info=True)
                        await self._send_discord_alert(f"Error en '{module_name}': {str(e)}")
        execution_time = time.time() - start_time
        # No insertar hallazgos para eventos del pipeline
        # await self.db.insert_finding_async(
        #     program_name, program_name, "", f"Pipeline completado en {execution_time:.2f}s", "Pipeline", 0.0
        # )
        log.info(f"Pipeline completado para '{program_name}' en {execution_time:.2f} segundos")

    def _run_module(self, module: Any, data: Any, program_name: Optional[str]):
        """Ejecuta un módulo con los datos proporcionados."""
        module_name = module.__class__.__name__
        input_for_module = program_name if module_name == "IntelModule" else data
        return module.run(input_for_module)

    async def run_single_module(self, module_name: str, program_name: Optional[str] = None):
        """Ejecuta un módulo específico."""
        log.info(f"Ejecutando módulo: '{module_name}'")
        for module in self.modules:
            if module.__class__.__name__ == module_name:
                try:
                    result = self._run_module(module, program_name if module_name == "IntelModule" else None, program_name)
                    log.info(f"Módulo '{module_name}' ejecutado.")
                    return result
                except Exception as e:
                    log.error(f"Error al ejecutar '{module_name}': {e}", exc_info=True)
                    await self._send_discord_alert(f"Error ejecutando '{module_name}': {str(e)}")
                    sys.exit(1)
        log.error(f"Módulo no encontrado: '{module_name}'")
        sys.exit(1)

    async def _send_discord_alert(self, message: str):
        """Envía una alerta a Discord si está configurado."""
        if not self.discord_webhook:
            return
        try:
            embed = {
                "title": "CazaDivina Alerta",
                "description": message,
                "color": 0xFF0000,
                "timestamp": datetime.now().isoformat()
            }
            data = {"embeds": [embed]}
            requests.post(self.discord_webhook, json=data, timeout=5)
            log.info("Alerta de Discord enviada.")
        except requests.exceptions.RequestException as e:
            log.error(f"Error al enviar alerta a Discord: {e}")

async def main():
    """Función principal que maneja los argumentos y ejecuta el pipeline."""
    parser = argparse.ArgumentParser(description="CazaDivina Pipeline")
    parser.add_argument("--target-program", help="Nombre del programa objetivo")
    parser.add_argument("--update-intel-only", action="store_true", help="Actualiza solo IntelModule")
    parser.add_argument("--modules", nargs='+', help="Módulos específicos")
    parser.add_argument("--config", default="config.yaml", help="Archivo de configuración")
    args = parser.parse_args()
    orchestrator = Orchestrator(config_file=args.config)
    await orchestrator.initialize()
    if args.update_intel_only:
        await orchestrator.run_single_module("IntelModule", args.target_program)
    elif args.target_program:
        await orchestrator.run_full_pipeline(args.target_program, args.modules)
    else:
        log.warning("No se especificó programa objetivo.")
        parser.print_help()
        sys.exit(1)
    await orchestrator.db.close_all()

if __name__ == "__main__":
    asyncio.run(main())
