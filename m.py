#!/usr/bin/env python3
# main.py
"""
Este archivo es el punto de entrada principal para el pipeline de CazaDivina.
Carga la configuración desde config.yaml, inicializa módulos y ejecuta pruebas de seguridad.
Usa concurrencia para ejecutar módulos en paralelo, registra logs en formato JSON y envía logs a Telegram en tiempo real.
"""

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
from concurrent.futures import ThreadPoolExecutor, as_completed  # Para ejecutar tareas en paralelo
from datetime import datetime  # Para obtener la fecha y hora
from typing import Dict, List, Optional, Any  # Para definir tipos de datos
from graphlib import TopologicalSorter, CycleError  # Para validar dependencias

# Importaciones locales
from modules.database import Database  # Clase para interactuar con la base de datos
from modules.tool_wrapper import run_tool, is_tool_available  # Funciones para ejecutar herramientas
from modules.telegram_reporter import setup_telegram_logging  # Módulo para enviar logs a Telegram

# Configuración de Logging estructurado
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
        return json.dumps(log_entry, ensure_ascii=False)

# Configura el logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)  # Cambiado a DEBUG para capturar más detalles
file_handler = logging.handlers.RotatingFileHandler(
    filename='output/system.log', maxBytes=10*1024*1024, backupCount=5
)
file_handler.setFormatter(JsonFormatter())
log.addHandler(file_handler)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(JsonFormatter())
log.addHandler(console_handler)

class Orchestrator:
    """
    Clase Orchestrator: Coordina la ejecución de módulos en el pipeline.
    Carga la configuración, inicializa la base de datos y ejecuta módulos respetando dependencias.
    """
    def __init__(self, config_file: str = "config.yaml"):
        """
        Inicializa el orquestador con un archivo de configuración.
        Args:
            config_file: Ruta al archivo config.yaml (por defecto: "config.yaml").
        """
        self.db = None
        self.modules: List[Any] = []
        self.config: Dict[str, Any] = {}
        self.scope: Dict[str, Any] = {}
        self.module_dependencies: Dict[str, List[str]] = {}
        self.max_workers = min(10, psutil.cpu_count(logical=True) * 2 or 1)
        self.module_timeout = 600  # Timeout por módulo en segundos
        self._load_config(config_file)

    async def initialize(self):
        """
        Inicializa la base de datos, valida el entorno y configura logging para Telegram.
        """
        try:
            log.info("Inicializando orquestador...")
            setup_telegram_logging()  # Configura el envío de logs a Telegram
            self.db = await Database()
            await self.validate_environment()
            self._validate_module_dependencies()
            log.info("Orquestador inicializado correctamente.")
        except Exception as e:
            log.error(f"Error al inicializar orquestador: {e}", exc_info=True)
            sys.exit(1)

    def _load_config(self, config_file: str):
        """
        Carga y valida el archivo de configuración (config.yaml).
        Args:
            config_file: Ruta al archivo de configuración.
        """
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or {}
            self._validate_config_schema()
            self.module_dependencies = self.config.get('module_dependencies', {})
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
                if module_name not in module_map:
                    log.warning(f"Módulo desconocido en config.yaml: {module_name}")
                    continue
                try:
                    module = importlib.import_module(f"modules.{module_map[module_name]}")
                    module_instance = getattr(module, module_name)()
                    if asyncio.iscoroutinefunction(module_instance.run):
                        module_instance.run = self._wrap_async_run(module_instance.run)
                    self.modules.append(module_instance)
                    log.info(f"Módulo '{module_name}' cargado exitosamente.")
                except (ImportError, AttributeError) as e:
                    log.error(f"Error al cargar '{module_name}': {e}", exc_info=True)
                    sys.exit(1)
            self.scope = self.config.get('scope', {})
            self.module_timeout = self.config.get('module_timeout', 600)
        except FileNotFoundError:
            log.error(f"Archivo de configuración '{config_file}' no encontrado.")
            sys.exit(1)
        except yaml.YAMLError as ye:
            log.error(f"Error de formato YAML en '{config_file}': {ye}", exc_info=True)
            sys.exit(1)
        except Exception as e:
            log.error(f"Error al cargar configuración: {e}", exc_info=True)
            sys.exit(1)

    def _wrap_async_run(self, async_run):
        """
        Convierte un método asíncrono en síncrono para compatibilidad con ThreadPoolExecutor.
        Usa un nuevo bucle de eventos para evitar conflictos.
        Args:
            async_run: Método asíncrono a envolver.
        Returns:
            Función síncrona que ejecuta el método asíncrono.
        """
        def sync_run(*args, **kwargs):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(async_run(*args, **kwargs))
            finally:
                loop.close()
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

    def _validate_module_dependencies(self):
        """
        Verifica que no haya ciclos en las dependencias de los módulos.
        Usa TopologicalSorter para detectar ciclos.
        """
        try:
            sorter = TopologicalSorter(self.module_dependencies)
            list(sorter.static_order())
        except CycleError as e:
            log.error(f"Ciclo detectado en las dependencias de los módulos: {e}")
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
        """
        Ejecuta todos los módulos en el pipeline para un programa dado.
        Respeta las dependencias entre módulos y usa concurrencia.
        Args:
            program_name: Nombre del programa objetivo (por ejemplo, "test").
            selected_modules: Lista opcional de módulos a ejecutar.
        """
        start_time = time.time()
        log.info(f"Iniciando pipeline para: '{program_name}'")
        data: Any = program_name
        executed_module_names = set()
        modules_to_run = [
            m for m in self.modules if not selected_modules or m.__class__.__name__ in selected_modules
        ]
        if not modules_to_run:
            log.warning("No hay módulos para ejecutar.")
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
                for future in as_completed(futures, timeout=self.module_timeout):
                    module_name = futures[future]
                    module_start = time.time()
                    try:
                        result = future.result()
                        if result is not None:
                            data = result
                        module_duration = time.time() - module_start
                        log.info(f"Módulo '{module_name}' completado en {module_duration:.2f} segundos.")
                        executed_module_names.add(module_name)
                    except TimeoutError:
                        log.error(f"Timeout en módulo '{module_name}' después de {self.module_timeout} segundos.")
                    except Exception as e:
                        log.error(f"Error en '{module_name}': {e}", exc_info=True)

        execution_time = time.time() - start_time
        log.info(f"Pipeline completado para '{program_name}' en {execution_time:.2f} segundos")

    def _run_module(self, module: Any, data: Any, program_name: Optional[str]):
        """
        Ejecuta un módulo con los datos proporcionados.
        Args:
            module: Instancia del módulo a ejecutar.
            data: Datos de entrada para el módulo.
            program_name: Nombre del programa objetivo.
        Returns:
            Resultado del módulo (puede ser None).
        """
        module_name = module.__class__.__name__
        input_for_module = program_name if module_name == "IntelModule" else data
        try:
            return module.run(input_for_module)
        except Exception as e:
            log.error(f"Error ejecutando módulo '{module_name}' para '{program_name}': {e}", exc_info=True)
            raise

    async def run_single_module(self, module_name: str, program_name: Optional[str] = None):
        """
        Ejecuta un módulo específico.
        Args:
            module_name: Nombre del módulo a ejecutar (por ejemplo, "ReconModule").
            program_name: Nombre del programa objetivo (opcional).
        Returns:
            Resultado del módulo.
        """
        log.info(f"Ejecutando módulo: '{module_name}'")
        for module in self.modules:
            if module.__class__.__name__ == module_name:
                start_time = time.time()
                try:
                    result = self._run_module(module, program_name if module_name == "IntelModule" else None, program_name)
                    duration = time.time() - start_time
                    log.info(f"Módulo '{module_name}' ejecutado en {duration:.2f} segundos.")
                    return result
                except Exception as e:
                    log.error(f"Error al ejecutar '{module_name}': {e}", exc_info=True)
                    sys.exit(1)
        log.error(f"Módulo no encontrado: '{module_name}'")
        sys.exit(1)

    async def _send_discord_alert(self, message: str):
        """
        Envía una alerta a Discord (desactivado porque no se usa).
        Args:
            message: Mensaje de la alerta.
        """
        log.debug(f"Alerta de Discord desactivada: {message}")
        return

async def main():
    """
    Función principal que maneja los argumentos y ejecuta el pipeline.
    """
    parser = argparse.ArgumentParser(description="CazaDivina Pipeline")
    parser.add_argument("--target-program", help="Nombre del programa objetivo")
    parser.add_argument("--update-intel-only", action="store_true", help="Actualiza solo IntelModule")
    parser.add_argument("--modules", nargs='+', help="Módulos específicos")
    parser.add_argument("--config", default="config.yaml", help="Archivo de configuración")
    args = parser.parse_args()

    try:
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
    except KeyboardInterrupt:
        log.info("Pipeline interrumpido por el usuario.")
        sys.exit(0)
    except Exception as e:
        log.error(f"Error inesperado en el pipeline: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if 'orchestrator' in locals() and orchestrator.db:
            await orchestrator.db.close_all()
            log.info("Conexiones a la base de datos cerradas.")

if __name__ == "__main__":
    asyncio.run(main())
