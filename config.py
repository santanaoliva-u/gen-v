# config.py
import os
<<<<<<< Updated upstream
from pathlib import Path
import yaml
=======
import yaml
from pathlib import Path
import logging

log = logging.getLogger(__name__)
>>>>>>> Stashed changes

# Directorio base
BASE_DIR = Path(__file__).resolve().parent

<<<<<<< Updated upstream
# Ruta de la base de datos
DB_PATH = str(BASE_DIR / "gen_vi.db")

# Cargar configuraciones desde config.yaml
CONFIG_FILE = BASE_DIR / "config.yaml"
CONFIG = {}
if CONFIG_FILE.exists():
    with open(CONFIG_FILE, 'r') as f:
        CONFIG = yaml.safe_load(f) or {}

# Configuraciones predeterminadas
NGROK_URL = CONFIG.get('ngrok_url', 'https://42a4-189-174-167-213.ngrok-free.app')
BASE_WORDLIST_DIR = CONFIG.get('wordlist_dir', '/usr/share/wordlists')
MAX_CONCURRENT_REQUESTS = CONFIG.get('max_concurrent_requests', 50)
REPORT_DIR = str(BASE_DIR / "output" / "reports")
LOG_DIR = str(BASE_DIR / "output" / "logs")
=======
# Cargar o crear config.yaml
CONFIG_FILE = BASE_DIR / "config.yaml"
DEFAULT_CONFIG = {
    "database": {
        "path": str(BASE_DIR / "gen_vi.db")
    },
    "ngrok_url": "https://42a4-189-174-167-213.ngrok-free.app",
    "wordlist_dir": "/usr/share/wordlists",
    "max_concurrent_requests": 50,
    "timeout": 10,
    "max_retries": 3,
    "modules_enabled": ["DeepFuzzXSSModule"],
    "log_level": "INFO",
    "report_dir": str(BASE_DIR / "output" / "reports"),
    "log_dir": str(BASE_DIR / "output" / "logs")
}

def load_config():
    """Carga o crea config.yaml."""
    if not CONFIG_FILE.exists():
        try:
            CONFIG_FILE.parent.mkdir(exist_ok=True)
            with open(CONFIG_FILE, 'w') as f:
                yaml.safe_dump(DEFAULT_CONFIG, f)
            log.info(f"Archivo {CONFIG_FILE} creado con configuraciones predeterminadas")
        except Exception as e:
            log.error(f"Error creando {CONFIG_FILE}: {e}")
            raise
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f) or {}
        # Fusionar con predeterminados
        merged = DEFAULT_CONFIG.copy()
        merged.update(config)
        return merged
    except Exception as e:
        log.error(f"Error cargando {CONFIG_FILE}: {e}")
        return DEFAULT_CONFIG

CONFIG = load_config()

# Exportar configuraciones
DB_PATH = CONFIG["database"]["path"]
NGROK_URL = CONFIG["ngrok_url"]
BASE_WORDLIST_DIR = CONFIG["wordlist_dir"]
MAX_CONCURRENT_REQUESTS = CONFIG["max_concurrent_requests"]
TIMEOUT = CONFIG["timeout"]
MAX_RETRIES = CONFIG["max_retries"]
MODULES_ENABLED = CONFIG["modules_enabled"]
LOG_LEVEL = CONFIG["log_level"]
REPORT_DIR = CONFIG["report_dir"]
LOG_DIR = CONFIG["log_dir"]

# Validar paths
for path in [DB_PATH, REPORT_DIR, LOG_DIR]:
    try:
        Path(path).parent.mkdir(exist_ok=True)
    except Exception as e:
        log.error(f"Error creando directorio para {path}: {e}")

# Override con variables de entorno
DB_PATH = os.getenv("GENVI_DB_PATH", DB_PATH)
NGROK_URL = os.getenv("GENVI_NGROK_URL", NGROK_URL)
>>>>>>> Stashed changes
