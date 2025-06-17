# config.py
import os
from pathlib import Path
import yaml

# Directorio base
BASE_DIR = Path(__file__).resolve().parent

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
