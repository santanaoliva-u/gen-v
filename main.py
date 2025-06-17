# main.py
import argparse
import logging
import logging.handlers
import yaml
import importlib
import sys
import time
import json
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Any

# Importaciones de tus módulos locales
from database import Database
from utils.tool_wrapper import is_tool_available # Importa la función específica

# --- Configuración de Logging Estructurado ---
class JsonFormatter(logging.Formatter):
    """
    Formateador de logs que genera salidas en formato JSON.
    Incluye timestamp, nivel, módulo, mensaje, archivo y línea.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(), # Usa getMessage() para manejar % y argumentos
            "file": record.pathname,
            "line": record.lineno
        }
        return json.dumps(log_entry)

# Configuración del logger principal
log = logging.getLogger(__name__)
log.setLevel(logging.INFO) # Nivel por defecto a INFO, ajusta a DEBUG si necesitas más detalle

# Handler para archivo (RotatingFileHandler para gestionar el tamaño del archivo)
file_handler = logging.handlers.RotatingFileHandler(
    filename='output/system.log',
    maxBytes=10 * 1024 * 1024,  # 10MB
    backupCount=5
)
file_handler.setFormatter(JsonFormatter())
log.addHandler(file_handler)

# Handler para consola
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(JsonFormatter()) # También usa JSON en consola para consistencia
log.addHandler(console_handler)

# --- Clase Orchestrator ---
class Orchestrator:
    """
    Clase principal para orquestar la ejecución de los módulos de CazaDivina Gen-VI.
    Gestiona la carga de configuración, validación del entorno, ejecución de módulos
    en paralelo y la comunicación con la base de datos y Discord.
    """
    def __init__(self, config_file: str = "config.yaml"):
        self.db = Database()
        self.modules: List[Any] = [] # Usamos Any porque los módulos son de tipos variados
        self.config: Dict[str, Any] = {}
        self.scope: Dict[str, Any] = {}
        self.module_dependencies: Dict[str, List[str]] = {}
        self.max_workers = min(10, psutil.cpu_count(logical=True) * 2 or 1) # Asegura al menos 1 worker

        self.discord_webhook: Optional[str] = None
        self._load_config(config_file) # Usamos un método privado para la carga

        # Después de cargar la configuración, validamos el entorno
        self.validate_environment()

    def _load_config(self, config_file: str):
        """
        Carga y valida la configuración desde config.yaml.
        Método privado ya que solo se llama internamente.
        """
        try:
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f)
            self._validate_config_schema() # Validar el esquema antes de usar

            self.module_dependencies = self.config.get('module_dependencies', {})
            # Mapeo más robusto y centralizado para los módulos
            module_map = {
                'DeepFuzzXSSModule': 'deep_fuzz_xss',
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
                        module = importlib.import_module(f"modules.{module_file}")
                        # Instanciar el módulo y añadirlo a la lista
                        self.modules.append(getattr(module, module_name)())
                        log.info(f"Módulo '{module_name}' cargado exitosamente.")
                    except ImportError as ie:
                        log.error(f"Error al importar el archivo para el módulo '{module_name}': {ie}. Asegúrate de que '{module_file}.py' exista en la carpeta 'modules'.")
                        sys.exit(1)
                    except AttributeError as ae:
                        log.error(f"Error al encontrar la clase '{module_name}' en el archivo '{module_file}.py': {ae}. Asegúrate de que el nombre de la clase coincida.")
                        sys.exit(1)
                else:
                    log.warning(f"Módulo desconocido o no mapeado en config.yaml: {module_name}. Será ignorado.")

            self.scope = self.config.get('scope', {})
            self.discord_webhook = self.config.get('discord_webhook')

        except FileNotFoundError:
            log.error(f"Error: Archivo de configuración '{config_file}' no encontrado. Asegúrate de que exista.")
            sys.exit(1)
        except yaml.YAMLError as ye:
            log.error(f"Error de formato YAML en '{config_file}': {ye}. Revisa la sintaxis del archivo.")
            sys.exit(1)
        except Exception as e:
            log.error(f"Error inesperado al cargar la configuración: {e}", exc_info=True)
            sys.exit(1)

    def _validate_config_schema(self):
        """
        Valida el esquema básico de config.yaml.
        Método privado ya que solo se llama internamente.
        """
        required_keys = ['modules', 'scope']
        for key in required_keys:
            if key not in self.config:
                log.error(f"Falta clave requerida en config.yaml: '{key}'.")
                sys.exit(1)

        if not self.config['scope'].get('include'):
            log.error("El scope en config.yaml debe incluir al menos un dominio bajo la clave 'include'.")
            sys.exit(1)

    def validate_environment(self):
        """
        Verifica la disponibilidad de herramientas externas y la conexión a ngrok antes de iniciar.
        """
        log.info("Validando el entorno: herramientas y conexión a Ngrok.")
        required_tools = [
            'amass', 'subfinder', 'assetfinder', 'findomain', 'dnsx', 'httpx',
            'waybackurls', 'gau', 'katana', 'ffuf', 'gobuster', 'dirsearch', 'arjun'
        ]

        missing_tools = [tool for tool in required_tools if not is_tool_available(tool)]
        if missing_tools:
            log.error(f"Herramientas faltantes: {', '.join(missing_tools)}. Por favor, ejecuta 'setup.sh' o instálalas manualmente.")
            sys.exit(1)
        log.info("Todas las herramientas requeridas están disponibles.")

        # Validar Ngrok si está configurado
        ngrok_url = self.config.get('ngrok_url', 'http://localhost:4040/api/tunnels')
        try:
            response = requests.get(ngrok_url, timeout=5)
            response.raise_for_status() # Lanza una excepción para errores 4xx/5xx
            log.info(f"Conexión a Ngrok exitosa en {ngrok_url}.")
        except requests.exceptions.ConnectionError:
            log.error(f"Error: No se pudo conectar a Ngrok en {ngrok_url}. Asegúrate de que Ngrok esté corriendo.")
            sys.exit(1)
        except requests.exceptions.Timeout:
            log.error(f"Error: Tiempo de espera agotado al intentar conectar con Ngrok en {ngrok_url}.")
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            log.error(f"Error de Ngrok: {e}. Asegúrate de que la URL de Ngrok sea correcta y el servicio esté activo.")
            sys.exit(1)

    def run_full_pipeline(self, program_name: str, selected_modules: Optional[List[str]] = None):
        """
        Ejecuta el pipeline completo de módulos con paralelismo inteligente y manejo de dependencias.
        """
        start_time = time.time()
        log.info(f"--- Iniciando pipeline completo para el programa: '{program_name}' ---")

        # Registrar el inicio del pipeline en la base de datos
        run_id = self.db.execute_query(
            "INSERT INTO pipeline_runs (program_name, start_time, status) VALUES (?, ?, ?) RETURNING id",
            (program_name, datetime.now().isoformat(), 'RUNNING')
        ).fetchone()[0] # Obtener el ID del nuevo registro

        data: Any = program_name # El input inicial es el nombre del programa
        executed_module_names = set()
        
        # Filtrar módulos si se especificaron
        modules_to_run = [m for m in self.modules if not selected_modules or m.__class__.__name__ in selected_modules]
        
        if not modules_to_run:
            log.warning("No hay módulos para ejecutar. Verifica tu selección o configuración.")
            self.db.execute_query(
                "UPDATE pipeline_runs SET end_time = ?, status = ?, execution_time = ? WHERE id = ?",
                (datetime.now().isoformat(), 'COMPLETED_NO_MODULES', 0, run_id)
            )
            return

        # Para asegurar que los módulos se ejecuten en orden de dependencia,
        # necesitamos un bucle que priorice módulos sin dependencias pendientes.
        # Esto es una simplificación; un grafo de dependencias sería más robusto para casos complejos.
        
        # Diccionario para guardar futuros activos y sus nombres de módulo
        active_futures: Dict[Any, str] = {}
        
        # Bucle principal para la orquestación de módulos
        while len(executed_module_names) < len(modules_to_run):
            modules_ready_to_run = []
            for module in modules_to_run:
                module_name = module.__class__.__name__
                if module_name in executed_module_names or module_name in active_futures.values():
                    continue # Ya ejecutado o en ejecución

                dependencies = self.module_dependencies.get(module_name, [])
                if all(dep in executed_module_names for dep in dependencies):
                    modules_ready_to_run.append(module)
            
            if not modules_ready_to_run and not active_futures:
                # No hay módulos listos para ejecutar y no hay módulos activos,
                # esto podría indicar un ciclo de dependencia o un error de lógica.
                log.error("¡Advertencia! No hay módulos listos para ejecutar y no hay futuros activos. Posible ciclo de dependencia o error en la lógica de orquestación.")
                break # Salir para evitar un bucle infinito

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Enviar módulos listos para ejecución
                for module in modules_ready_to_run:
                    module_name = module.__class__.__name__
                    future = executor.submit(self._run_module, module, data, program_name)
                    active_futures[future] = module_name
            
                # Esperar a que los módulos terminen
                if active_futures: # Solo espera si hay futuros activos
                    done_futures, _ = as_completed(active_futures, timeout=None).__next__() # Espera al menos uno
                    
                    module_name_finished = active_futures.pop(done_futures) # Quita el futuro terminado
                    executed_module_names.add(module_name_finished)
                    
                    try:
                        result = done_futures.result()
                        if result is not None:
                            data = result # Actualizar los datos para el siguiente módulo
                        log.info(f"Módulo '{module_name_finished}' completado exitosamente.")
                    except Exception as e:
                        log.error(f"Error crítico en el módulo '{module_name_finished}': {e}", exc_info=True)
                        self._send_discord_alert(f"Error crítico en el módulo '{module_name_finished}': {str(e)}")
                        # Decidir si parar el pipeline o continuar (aquí se detiene)
                        self.db.execute_query(
                            "UPDATE pipeline_runs SET end_time = ?, status = ?, execution_time = ? WHERE id = ?",
                            (datetime.now().isoformat(), 'FAILED', time.time() - start_time, run_id)
                        )
                        log.error(f"Pipeline terminado prematuramente debido a un error en '{module_name_finished}'.")
                        return # Terminar la ejecución del pipeline

                time.sleep(0.1) # Pequeña pausa para evitar busy-waiting si no hay módulos listos

        execution_time = time.time() - start_time
        final_status = 'COMPLETED' if len(executed_module_names) == len(modules_to_run) else 'COMPLETED_WITH_WARNINGS'
        self.db.execute_query(
            "UPDATE pipeline_runs SET end_time = ?, status = ?, execution_time = ? WHERE id = ?",
            (datetime.now().isoformat(), final_status, execution_time, run_id)
        )
        log.info(f"--- Pipeline completado para: '{program_name}' en {execution_time:.2f} segundos ---")
        self._send_discord_alert(f"Pipeline completado para {program_name} en {execution_time:.2f}s")

    def run_single_module(self, module_name: str, program_name: Optional[str] = None):
        """
        Ejecuta un módulo específico por su nombre de clase.
        """
        log.info(f"Ejecutando módulo individual: '{module_name}'...")
        module_found = False
        for module in self.modules:
            if module.__class__.__name__ == module_name:
                module_found = True
                try:
                    # 'IntelModule' es especial porque toma el nombre del programa directamente
                    # Otros módulos tomarían 'data' que no está disponible aquí para un solo módulo.
                    # Asumimos que si no es IntelModule, puede funcionar sin un input complejo para una ejecución individual.
                    input_data = program_name if module_name == "IntelModule" else None # O ajustar según el módulo
                    result = self._run_module(module, input_data, program_name)
                    log.info(f"Módulo '{module_name}' ejecutado individualmente y completado.")
                    return result
                except Exception as e:
                    log.error(f"Error al ejecutar el módulo '{module_name}' individualmente: {e}", exc_info=True)
                    self._send_discord_alert(f"Error ejecutando '{module_name}': {str(e)}")
                    sys.exit(1) # Salir si falla un módulo individual
        
        if not module_found:
            log.error(f"Módulo no encontrado: '{module_name}'. Asegúrate de que el nombre sea correcto y esté configurado en 'config.yaml'.")
            sys.exit(1)

    def _run_module(self, module: Any, data: Any, program_name: Optional[str]):
        """
        Ejecuta un módulo con lógica de reintentos.
        Método privado ya que solo se llama internamente.
        """
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                log.info(f"Ejecutando módulo '{module.__class__.__name__}' (intento {attempt + 1}/{max_retries + 1})...")
                # Pasar 'program_name' si el módulo es IntelModule, de lo contrario 'data'.
                # Esto es crucial para la flexibilidad de los módulos.
                input_for_module = program_name if module.__class__.__name__ == "IntelModule" else data
                return module.run(input_for_module)
            except Exception as e:
                log.error(f"Error en '{module.__class__.__name__}' (intento {attempt + 1}): {e}", exc_info=True)
                if attempt < max_retries:
                    log.warning(f"Reintentando el módulo '{module.__class__.__name__}' en 2 segundos...")
                    time.sleep(2)
                else:
                    log.critical(f"El módulo '{module.__class__.__name__}' falló después de {max_retries + 1} intentos. Abortando.")
                    raise # Relanzar la excepción para que sea manejada por el orquestador

    def _send_discord_alert(self, message: str):
        """
        Envía una alerta a Discord si el webhook está configurado.
        Método privado ya que solo se llama internamente.
        """
        if not self.discord_webhook:
            return
        try:
            embed = {
                "title": "CazaDivina Gen-VI Alerta",
                "description": message,
                "color": 0xFF0000, # Rojo para alertas
                "timestamp": datetime.now().isoformat()
            }
            data = {"embeds": [embed]}
            requests.post(self.discord_webhook, json=data, timeout=5)
            log.info("Alerta de Discord enviada exitosamente.")
        except requests.exceptions.RequestException as e:
            log.error(f"Error al enviar alerta a Discord: {e}. Revisa la URL del webhook.")
        except Exception as e:
            log.error(f"Error inesperado al enviar alerta a Discord: {e}", exc_info=True)

# --- Función Principal ---
def main():
    """
    Función de entrada principal para el script CazaDivina Gen-VI.
    Configura el analizador de argumentos y delega la ejecución al Orchestrator.
    """
    parser = argparse.ArgumentParser(
        description="CazaDivina Gen-VI Pipeline de Seguridad Ofensiva Inteligente",
        formatter_class=argparse.RawTextHelpFormatter # Para formato de ayuda con saltos de línea
    )
    parser.add_argument(
        "--target-program",
        help="Nombre del programa de bug bounty o dominio objetivo (ej: 'www.google.com' o 'MiPrograma')."
    )
    parser.add_argument(
        "--update-intel-only",
        action="store_true",
        help="Actualiza solo el 'IntelModule' para recopilar información más reciente."
    )
    parser.add_argument(
        "--modules",
        nargs='+', # Permite 0 o más argumentos
        help="Ejecuta módulos específicos por sus nombres de clase (ej: --modules ReconModule ExecutionModule).\n"
             "Si no se especifica, se ejecutan todos los módulos configurados en 'config.yaml'."
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Ruta al archivo de configuración (por defecto: 'config.yaml')."
    )

    args = parser.parse_args()

    # Inicializar el orquestador con el archivo de configuración especificado
    orchestrator = Orchestrator(config_file=args.config)
    
    # Lógica de ejecución basada en los argumentos
    if args.update_intel_only:
        log.info("Modo 'actualizar solo IntelModule' activado.")
        orchestrator.run_single_module("IntelModule", None) # IntelModule necesita un programa, aquí lo pasamos como None o ajustar.
    elif args.target_program:
        log.info(f"Iniciando el pipeline para el programa objetivo: '{args.target_program}'.")
        orchestrator.run_full_pipeline(args.target_program, args.modules)
    else:
        log.warning("No se especificó un programa objetivo ni la opción de actualización de Intel. Mostrando ayuda.")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
