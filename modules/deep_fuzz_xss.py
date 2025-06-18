# modules/deep_fuzz_xss.py
import sys
import os
import logging
import logging.handlers
import urllib.parse
import random
import json
import time
import asyncio
import aiohttp
import base64
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Set, Dict, Optional, Coroutine
from pathlib import Path
import shutil # ANOTACIÓN: shutil se usa en _validate_tools, es mejor importarlo al principio.

# CORRECCIÓN: Se elimina la importación redundante. run_tool es la única función que se necesita.
from modules.tool_wrapper import run_tool
from modules.database import Database
import psutil
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from config import BASE_DIR, BASE_WORDLIST_DIR, MAX_CONCURRENT_REQUESTS, REPORT_DIR, LOG_DIR

# Ajustar sys.path
# ANOTACIÓN: Esto es funcional, pero para proyectos más grandes, considera una estructura de paquetes
# que haga innecesario manipular sys.path.
sys.path.append(str(BASE_DIR))

log = logging.getLogger(__name__)

# Configurar logging rotativo
os.makedirs(LOG_DIR, exist_ok=True)
handler = logging.handlers.RotatingFileHandler(
    f"{LOG_DIR}/vuln_report.log", maxBytes=10*1024*1024, backupCount=5
)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
log.addHandler(handler)
log.setLevel(logging.INFO)


class DeepFuzzXSSModule:
    def __init__(self):
        self.db = Database()
        self.program_name: Optional[str] = None
        self.ngrok_url: str = self._get_ngrok_url()
        self.base_dir = Path(BASE_WORDLIST_DIR)

        # CORRECCIÓN: El orden de inicialización importa. Payloads dependen de ngrok_url.
        self.xss_payloads: Set[str] = self._load_payloads_from_sources(self._get_xss_payload_sources(), self._process_xss_payload)
        log.info(f"Cargados {len(self.xss_payloads)} payloads XSS únicos")
        
        self.crlf_payloads: Set[str] = self._load_crlf_payloads()

        self.fuzz_params: List[str] = self._load_fuzz_params()
        self.user_agents: List[str] = self._load_user_agents()
        self.proxies: List[str] = self._load_proxies()
        self.max_workers: int = min(10, psutil.cpu_count(logical=True) * 2)

        # CORRECCIÓN: Eliminado queue.Queue. No es necesario y su uso era incorrecto en un entorno async.
        # La concurrencia se gestiona con el semáforo.
        
        self.cache_file: str = str(BASE_DIR / "output" / "xss_cache.json")
        self.cve_cache_file: str = str(BASE_DIR / "output" / "cve_cache.json")
        self.cache: Dict = self._load_cache(self.cache_file)
        self.cve_cache: Dict = self._load_cache(self.cve_cache_file)
        self.session_headers: Dict = self._initialize_headers()

        self.wordlists: Dict = self._load_wordlists()
        # CORRECCIÓN: Cargar recursos (extensiones, payloads) una sola vez para mejorar el rendimiento.
        self.extensions: List[str] = self._load_extensions()
        self.sqli_payloads: Set[str] = self._load_payloads_from_wordlist_category('sqli', 'SQLi')
        self.lfi_payloads: Set[str] = self._load_payloads_from_wordlist_category('lfi', 'LFI')
        self.cmd_injection_payloads: Set[str] = self._load_payloads_from_wordlist_category('cmd_injection', 'Command Injection')
        
        self.cve_scripts: List[Dict] = self._load_cve_scripts()
        self.nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.selenium_driver: Optional[webdriver.Chrome] = self._init_selenium()
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self.tools = ['ffuf', 'gobuster', 'dirsearch', 'arjun', 'wfuzz']
        # ANOTACIÓN: ThreadPoolExecutor para ejecutar tareas síncronas (como herramientas de CLI) en hilos separados.
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)


    def _get_ngrok_url(self) -> str:
        """Obtiene la URL de ngrok dinámicamente."""
        try:
            # CORRECCIÓN: Usar pathlib para construir la ruta es más robusto.
            payload_js_path = BASE_DIR / "modules" / "xss_server" / "public" / "payload.js"
            with open(payload_js_path, 'r') as f:
                content = f.read()
                match = re.search(r'https://[a-zA-Z0-9-]+\.ngrok-free\.app', content)
                if match:
                    log.info(f"URL de ngrok detectada: {match.group(0)}")
                    return match.group(0)
            log.warning("No se pudo detectar la URL de ngrok. Usando valor predeterminado.")
            # ANOTACIÓN: Este valor predeterminado expirará. Es mejor advertir al usuario.
            return "https://42a4-189-174-167-213.ngrok-free.app"
        except Exception as e:
            log.error(f"Error obteniendo URL de ngrok: {e}. Usando valor predeterminado.")
            return "https://42a4-189-174-167-213.ngrok-free.app"

    # REFACTOR: Se centraliza la lógica de carga de payloads para evitar duplicación de código.
    def _load_payloads_from_sources(self, sources: List[Path], processor: Coroutine) -> Set[str]:
        """Carga y procesa payloads desde una lista de directorios o archivos fuente."""
        payloads = set()
        for source in sources:
            if source.is_dir():
                for file in source.rglob("*.txt"): # rglob busca recursivamente
                    try:
                        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                processor(line.strip(), payloads)
                    except Exception as e:
                        log.error(f"Error cargando payloads de {file}: {e}")
            elif source.is_file():
                try:
                    with open(source, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            processor(line.strip(), payloads)
                except Exception as e:
                    log.error(f"Error cargando payloads de {source}: {e}")
        return payloads

    def _process_xss_payload(self, payload: str, payloads: Set[str]):
        """Procesa y añade variaciones de un payload XSS."""
        if payload and not payload.startswith('#'):
            payloads.add(payload)
            payloads.add(urllib.parse.quote(payload))
            payloads.add(urllib.parse.quote_plus(payload))
            # ANOTACIÓN: Las codificaciones más exóticas pueden aumentar la detección de WAF, úsalas con cuidado.
            # payloads.add(f"UTF-7:+ADw-script+AD4-{urllib.parse.quote(payload)}+ADw-/script+AD4-")
            payloads.add(f"data:text/html;base64,{base64.b64encode(payload.encode()).decode()}")
    
    def _get_xss_payload_sources(self) -> List[Path]:
        """Devuelve una lista de rutas de donde cargar los payloads XSS."""
        return [
            self.base_dir / "fuzzdb" / "attack" / "xss",
            self.base_dir / "SecLists" / "Fuzzing" / "XSS",
            self.base_dir / "SecLists" / "Fuzzing" / "Polyglots",
            self.base_dir / "PayloadsAllTheThings" / "XSS Injection",
            BASE_DIR / "xss_payloads.txt"
        ]

    def _load_crlf_payloads(self) -> Set[str]:
        """Carga payloads CRLF."""
        payloads = set()
        crlf_file = self.base_dir / "PayloadsAllTheThings" / "CRLF Injection" / "Files" / "crlfinjection.txt"
        if crlf_file.exists():
            try:
                with open(crlf_file, 'r', encoding='utf-8') as f:
                    payloads.update(line.strip() for line in f if line.strip())
                log.info(f"Cargados {len(payloads)} payloads CRLF.")
            except Exception as e:
                log.error(f"Error cargando CRLF payloads: {e}")
        return payloads

    def _load_payloads_from_wordlist_category(self, category: str, log_name: str) -> Set[str]:
        """Carga payloads genéricos (SQLi, LFI, etc.) desde una categoría de wordlist."""
        payloads = set()
        for path in self.wordlists.get(category, []):
            sources = []
            if path.is_dir():
                sources.extend(path.rglob("*.txt"))
            elif path.is_file():
                sources.append(path)
            
            for file in sources:
                try:
                    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                        payloads.update(line.strip() for line in f if line.strip() and not line.startswith('#'))
                except Exception as e:
                    log.error(f"Error cargando payloads {log_name} de {file}: {e}")
        
        log.info(f"Cargados {len(payloads)} payloads de {log_name}.")
        return payloads


    def _load_fuzz_params(self) -> List[str]:
        """Carga parámetros para fuzzing."""
        params = {'id', 'q', 'search', 'name', 'value', 'page', 'user', 'token', 'key', 'query', 'callback', 'url', 'redirect', 'next'}
        sources = [
            self.base_dir / "fuzzdb" / "wordlists-misc" / "params.txt",
            self.base_dir / "SecLists" / "Discovery" / "Variables" / "params.txt"
        ]
        for source in sources:
            if source.exists():
                try:
                    with open(source, 'r', encoding='utf-8', errors='ignore') as f:
                        params.update(line.strip() for line in f if line.strip() and not line.startswith('#'))
                except Exception as e:
                    log.error(f"Error cargando parámetros de {source}: {e}")
        log.info(f"Cargados {len(params)} parámetros de fuzzing.")
        return list(params)


    def _load_user_agents(self) -> List[str]:
        """Carga user-agents para rotación."""
        user_agents = []
        sources = [
            self.base_dir / "fuzzdb" / "wordlists-misc" / "user-agents.txt",
            self.base_dir / "SecLists" / "Fuzzing" / "User-Agents" / "user-agents.txt",
            BASE_DIR / "user_agents.txt"
        ]
        for source in sources:
            if source.exists():
                try:
                    with open(source, 'r', encoding='utf-8', errors='ignore') as f:
                        user_agents.extend(line.strip() for line in f if line.strip() and not line.startswith('#'))
                except Exception as e:
                    log.error(f"Error cargando user-agents de {source}: {e}")
        
        if not user_agents:
            log.warning("No se encontraron listas de user-agents. Usando uno por defecto.")
            return ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36']
        
        log.info(f"Cargados {len(user_agents)} user-agents.")
        return user_agents


    def _load_proxies(self) -> List[str]:
        """Carga proxies para evasión WAF."""
        proxies = []
        source = BASE_DIR / "proxies.txt"
        if source.exists():
            try:
                with open(source, 'r', encoding='utf-8') as f:
                    proxies = [line.strip() for line in f if line.strip()]
                log.info(f"Cargados {len(proxies)} proxies.")
            except Exception as e:
                log.error(f"Error cargando proxies: {e}")
        return proxies

    def _load_wordlists(self) -> Dict:
        """Carga rutas de wordlists para fuzzing."""
        # ANOTACIÓN: Es más limpio y mantenible definir las rutas y luego validarlas.
        base_paths = {
            'dirs': [
                self.base_dir / "SecLists" / "Discovery" / "Web-Content" / "common.txt",
                self.base_dir / "SecLists" / "Discovery" / "Web-Content" / "big.txt"
            ],
            'files': [
                self.base_dir / "SecLists" / "Discovery" / "Web-Content" / "raft-large-files.txt"
            ],
            'extensions': [
                self.base_dir / "SecLists" / "Discovery" / "Web-Content" / "web-extensions.txt",
                self.base_dir / "fuzzdb" / "discover" / "extensions" / "html.txt"
            ],
            'sqli': [
                self.base_dir / "SecLists" / "Fuzzing" / "SQLi",
                self.base_dir / "PayloadsAllTheThings" / "SQL Injection"
            ],
            'lfi': [ self.base_dir / "SecLists" / "Fuzzing" / "LFI" ],
            'cmd_injection': [ self.base_dir / "PayloadsAllTheThings" / "Command Injection" ],
            'backdoors': [ self.base_dir / "SecLists" / "Web-Shells" / "backdoor-list.txt" ],
            'flash': [ self.base_dir / "SecLists" / "Payloads" / "Flash" / "xssproject.swf" ],
            'antivirus': [ self.base_dir / "SecLists" / "Payloads" / "Anti-Virus" / "eicar.com.txt" ]
        }
        # Valida que las rutas existan
        loaded_wordlists = {}
        for key, paths in base_paths.items():
            valid_paths = [p for p in paths if p.exists()]
            if valid_paths:
                loaded_wordlists[key] = valid_paths
        return loaded_wordlists

    def _load_cve_scripts(self) -> List[Dict]:
        """Carga scripts CVE en Python."""
        cve_dir = self.base_dir / "PayloadsAllTheThings" / "CVE Exploits"
        scripts = []
        if cve_dir.is_dir():
            for file in cve_dir.rglob("*.py"):
                cve_id_match = re.search(r'CVE-\d{4}-\d+', file.stem, re.IGNORECASE)
                if cve_id_match:
                    scripts.append({
                        'name': file.name,
                        'path': str(file),
                        'cve_id': cve_id_match.group(0).upper()
                    })
        log.info(f"Cargados {len(scripts)} scripts de exploits CVE.")
        return scripts

    def _init_selenium(self) -> Optional[webdriver.Chrome]:
        """Inicializa Selenium para DOM XSS."""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            # ANOTACIÓN: Deshabilitar la política de seguridad puede ser necesario para algunas pruebas
            # pero aumenta el riesgo si se navega a sitios no confiables.
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            return webdriver.Chrome(options=chrome_options)
        except Exception as e:
            log.error(f"Error inicializando Selenium: {e}. El análisis de DOM XSS estará deshabilitado.")
            return None

    def _load_cache(self, cache_file: str) -> Dict:
        """Carga caché de resultados."""
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            log.error(f"Error cargando caché {cache_file}: {e}. Se creará una nueva.")
        return {}

    def _save_cache(self, cache_file: str, data: Dict):
        """Guarda caché de resultados."""
        try:
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except IOError as e:
            log.error(f"Error guardando caché {cache_file}: {e}")

    def _initialize_headers(self) -> Dict:
        """Inicializa headers para solicitudes."""
        # ANOTACIÓN: Usar Referer y Origin fijos puede no ser óptimo. Podrían adaptarse al host objetivo.
        return {
            'User-Agent': self._get_random_user_agent(),
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Referer': 'https://google.com',
            'Origin': 'https://google.com',
            'X-Forwarded-For': f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            'X-Real-IP': f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            'X-Requested-With': 'XMLHttpRequest'
        }

    def _validate_tools(self):
        """Valida la existencia de herramientas requeridas."""
        for tool in self.tools:
            if not shutil.which(tool):
                log.error(f"Herramienta requerida '{tool}' no encontrada en el PATH. Instálala para continuar.")
                raise FileNotFoundError(f"Herramienta {tool} no encontrada. El módulo no puede continuar.")

    async def run(self, data: tuple) -> tuple:
        """Ejecuta el módulo de fuzzing y análisis de vulnerabilidades."""
        try:
            self._validate_tools()
        except FileNotFoundError as e:
            log.critical(e)
            return ([], [])

        live_hosts, endpoints = data if isinstance(data, tuple) and len(data) == 2 else ([], [])
        # ANOTACIÓN: El nombre del programa debería ser un parámetro, no estar hardcodeado.
        self.program_name = "Valve" 
        log.info(f"Iniciando DeepFuzz en {len(live_hosts)} hosts vivos y {len(endpoints)} endpoints iniciales...")

        async with aiohttp.ClientSession(headers=self.session_headers) as session:
            tasks = [self._process_host(session, host, endpoints) for host in live_hosts]
            # CORRECCIÓN: Manejar excepciones de `gather` para evitar que una tarea fallida detenga todo.
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            discovered_endpoints = set(endpoints)
            for res in results:
                if isinstance(res, list):
                    discovered_endpoints.update(res)
                elif isinstance(res, Exception):
                    log.error(f"Error procesando un host: {res}")
            
            endpoints = list(discovered_endpoints)

        self._save_cache(self.cache_file, self.cache)
        self._save_cache(self.cve_cache_file, self.cve_cache)
        await self._generate_report()
        
        if self.selenium_driver:
            self.selenium_driver.quit()
        # CORRECCIÓN: Asumimos que close() es asíncrono en una app async.
        await self.db.close()
        
        return live_hosts, endpoints
    
    # CORRECCIÓN: El método `_process_host` se ha simplificado eliminando la lógica de la cola.
    async def _process_host(self, session: aiohttp.ClientSession, host: str, existing_endpoints: list) -> List[str]:
        """Procesa un host individual: fuzzing y análisis de vulnerabilidades."""
        log.info(f"Comenzando procesamiento completo para el host: {host}")
        
        fuzzed_endpoints = await self.perform_fuzzing(host)
        
        all_endpoints = set(fuzzed_endpoints)
        for ep in existing_endpoints:
            # Asegurarse de que solo se procesan endpoints relevantes para el host actual
            if host in urllib.parse.urlparse(ep).netloc:
                all_endpoints.add(ep)
        
        log.info(f"Host {host}: {len(all_endpoints)} endpoints para analizar (existentes + descubiertos).")
        endpoints_to_scan = list(all_endpoints)
        
        # Ejecutar análisis en paralelo
        analysis_tasks = [
            self.perform_xss_analysis(session, host, endpoints_to_scan),
            self.perform_sqli_analysis(session, host, endpoints_to_scan),
            self.perform_lfi_analysis(session, host, endpoints_to_scan),
            self.perform_cmd_injection_analysis(session, host, endpoints_to_scan),
            self.perform_crlf_analysis(session, host, endpoints_to_scan),
            self.perform_upload_analysis(session, host, endpoints_to_scan),
            self.detect_backdoors(host),
            self.test_cve_exploits(host)
        ]
        await asyncio.gather(*analysis_tasks, return_exceptions=True)
        
        return fuzzed_endpoints

    # ... (métodos de fuzzing y análisis, ver cambios abajo) ...
    # El resto de métodos se mantienen muy similares, pero se adaptan a las
    # cargas de payloads en `__init__` y al uso correcto del executor.

    # Ejemplo de método de análisis refactorizado
    async def perform_sqli_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        """Analiza endpoints para vulnerabilidades SQLi usando payloads precargados."""
        log.info(f"Analizando SQLi en {host}...")
        # CORRECCIÓN: Usar los payloads cargados en __init__ en lugar de cargarlos aquí.
        await self._test_injection(session, host, endpoints, self.sqli_payloads, "SQLi")


    async def perform_fuzzing(self, host: str) -> List[str]:
        """Realiza fuzzing en el host para descubrir directorios, archivos y parámetros."""
        log.info(f"Realizando fuzzing en {host}...")
        cache_key = f"fuzz_{host}"
        if cache_key in self.cache:
            log.info(f"Resultados de fuzzing para {host} cargados desde caché.")
            return self.cache[cache_key]

        new_endpoints = set()
        
        # Generar tareas para herramientas de fuzzing de directorios/archivos
        tool_configs = []
        wordlists = self.wordlists.get('dirs', []) + self.wordlists.get('files', [])
        for wordlist_path in wordlists:
            tool_configs.extend(self._get_fuzz_tools(host, wordlist_path))

        # CORRECCIÓN: Ejecutar herramientas en el ThreadPoolExecutor de forma asíncrona.
        loop = asyncio.get_running_loop()
        fuzz_tasks = [loop.run_in_executor(self.executor, self._run_fuzz_tool, config) for config in tool_configs]
        
        for future in asyncio.as_completed(fuzz_tasks):
            try:
                result_endpoints = await future
                new_endpoints.update(result_endpoints)
            except Exception as e:
                log.error(f"Error en una tarea de fuzzing: {e}")
        
        log.info(f"Fuzzing de directorios/archivos en {host} encontró {len(new_endpoints)} endpoints.")
        
        # Ahora, fuzz de parámetros en los endpoints encontrados.
        if new_endpoints:
            # ANOTACIÓN: Para simplificar, arjun se ejecuta sobre el host base.
            # Podría extenderse para ejecutarlo sobre cada endpoint encontrado.
            log.info(f"Iniciando fuzzing de parámetros con arjun en {host}")
            arjun_config = {
                'tool': 'arjun',
                'command': ["arjun", "-u", f"https://{host}", "--stable", "-oJ", f"output/{host}_arjun.json"],
                'output_file': f"output/{host}_arjun.json",
                'output_parser': self._parse_arjun_output
            }
            try:
                param_endpoints = await loop.run_in_executor(self.executor, self._run_fuzz_tool, arjun_config)
                new_endpoints.update(param_endpoints)
            except Exception as e:
                log.error(f"Error ejecutando arjun: {e}")

        final_endpoints = list(new_endpoints)
        self.cache[cache_key] = final_endpoints
        log.info(f"Fuzzing total en {host} finalizado. {len(final_endpoints)} endpoints descubiertos.")
        return final_endpoints


    def _get_fuzz_tools(self, host: str, wordlist: Path) -> List[Dict]:
        """Genera configuraciones para herramientas de fuzzing de directorios/archivos."""
        # CORRECCIÓN: Usar self.extensions, que ya está cargado.
        ext_str = ",".join(self.extensions)
        output_dir = BASE_DIR / "output"
        output_dir.mkdir(exist_ok=True)
        
        base_filename = f"{host}__{wordlist.stem}" # Usar un separador claro

        # ANOTACIÓN: `-s` en ffuf suprime la salida a stdout, lo que es bueno para la ejecución de scripts.
        return [
            {
                'tool': 'ffuf',
                'command': ["ffuf", "-u", f"https://{host}/FUZZ", "-w", str(wordlist), "-e", ext_str, "-mc", "200,301,302,307,403", "-s", "-o", str(output_dir / f"{base_filename}_ffuf.json"), "-of", "json"],
                'output_file': str(output_dir / f"{base_filename}_ffuf.json"),
                'output_parser': self._parse_ffuf_output
            },
            # Se pueden añadir otras herramientas aquí como antes...
        ]

    # ... otros métodos como `_load_extensions`, `_run_fuzz_tool`, parsers, etc. sin cambios significativos
    
    # ... `perform_xss_analysis` se ve similar pero llama a los _test_...
    async def perform_xss_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        """Analiza endpoints para vulnerabilidades XSS."""
        log.info(f"Analizando XSS en {host} con {len(endpoints)} endpoints...")
        
        tasks = []
        for endpoint in endpoints:
            if f"xss_{endpoint}" in self.cache:
                continue
            tasks.append(self._test_xss_on_endpoint(session, host, endpoint))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_xss_on_endpoint(self, session: aiohttp.ClientSession, host: str, endpoint: str):
        """Prueba todas las técnicas de XSS en un único endpoint."""
        async with self.semaphore:
            parsed = urllib.parse.urlparse(endpoint)
            query_params = urllib.parse.parse_qs(parsed.query)

            if not query_params: # No hay parámetros para probar en este endpoint
                return
            
            # Seleccionar un subconjunto de payloads para no ser demasiado ruidoso
            payloads_sample = random.sample(list(self.xss_payloads), min(20, len(self.xss_payloads)))

            for param in query_params:
                for payload in payloads_sample:
                    # Crear tareas para diferentes vectores de ataque
                    await asyncio.gather(
                        self._test_reflected_xss(session, host, endpoint, param, payload),
                        self._test_dom_xss(host, endpoint, param, payload), # Selenium es síncrono, se maneja aparte
                        self._test_post_xss(session, host, endpoint, param, payload),
                        # Otros tests...
                        return_exceptions=True
                    )
            
            self.cache[f"xss_{endpoint}"] = True
    
    # ... el resto de los métodos se adaptarían de manera similar.
    # -------------------------------------------------------------------------
    # MÉTODOS DE FUZZING Y DESCUBRIMIENTO
    # -------------------------------------------------------------------------

    async def perform_fuzzing(self, host: str) -> List[str]:
        """Realiza fuzzing en el host para descubrir directorios, archivos y parámetros."""
        log.info(f"Realizando fuzzing en {host}...")
        cache_key = f"fuzz_{host}"
        if cache_key in self.cache:
            log.info(f"Resultados de fuzzing para {host} cargados desde caché.")
            return self.cache[cache_key]

        new_endpoints = set()
        loop = asyncio.get_running_loop()

        # 1. Fuzzing de Directorios y Archivos
        tool_configs = []
        wordlists = self.wordlists.get('dirs', []) + self.wordlists.get('files', [])
        for wordlist_path in wordlists:
            tool_configs.extend(self._get_fuzz_tools(host, wordlist_path))

        # CORRECCIÓN: Ejecuta las herramientas síncronas en un ThreadPoolExecutor para no bloquear el bucle de eventos.
        fuzz_tasks = [loop.run_in_executor(self.executor, self._run_fuzz_tool, config) for config in tool_configs]
        for future in asyncio.as_completed(fuzz_tasks):
            try:
                result_endpoints = await future
                new_endpoints.update(result_endpoints)
            except Exception as e:
                log.error(f"Error en una tarea de fuzzing de directorio/archivo: {e}")

        # 2. Fuzzing de Parámetros
        log.info(f"Iniciando fuzzing de parámetros con Arjun en https://{host}")
        arjun_config = {
            'tool': 'arjun',
            'command': ["arjun", "-u", f"https://{host}", "--stable", "-oJ", str(BASE_DIR / "output" / f"{host}_arjun.json")],
            'output_file': str(BASE_DIR / "output" / f"{host}_arjun.json"),
            'output_parser': self._parse_arjun_output
        }
        try:
            # CORRECCIÓN: También se ejecuta en el executor.
            param_endpoints = await loop.run_in_executor(self.executor, self._run_fuzz_tool, arjun_config)
            new_endpoints.update(self._fuzz_parameters(host, param_endpoints))
        except Exception as e:
            log.error(f"Error ejecutando arjun: {e}")

        final_endpoints = list(new_endpoints)
        self.cache[cache_key] = final_endpoints
        log.info(f"Fuzzing total en {host} finalizado. {len(final_endpoints)} endpoints descubiertos.")
        return final_endpoints

    def _get_fuzz_tools(self, host: str, wordlist: Path) -> List[Dict]:
        """Genera configuraciones para herramientas de fuzzing de directorios/archivos."""
        # CORRECCIÓN: Usa `self.extensions` que fue cargado una sola vez en __init__.
        ext_str = ",".join(self.extensions)
        output_dir = BASE_DIR / "output"
        output_dir.mkdir(exist_ok=True)
        base_filename = f"{host.replace('.', '_')}__{wordlist.stem}"

        # ANOTACIÓN: Los comandos están optimizados para la automatización (salida JSON, sin modo interactivo).
        return [
            {
                'tool': 'ffuf',
                'command': ["ffuf", "-u", f"https://{host}/FUZZ", "-w", str(wordlist), "-e", ext_str, "-mc", "200,301,302,307,403", "-s", "-o", str(output_dir / f"{base_filename}_ffuf.json"), "-of", "json"],
                'output_file': str(output_dir / f"{base_filename}_ffuf.json"),
                'output_parser': self._parse_ffuf_output
            },
            {
                'tool': 'dirsearch',
                'command': ["dirsearch", "-u", f"https://{host}", "-w", str(wordlist), "-e", ext_str, "--json-report", str(output_dir / f"{base_filename}_dirsearch.json")],
                'output_file': str(output_dir / f"{base_filename}_dirsearch.json"),
                'output_parser': self._parse_dirsearch_output
            },
        ]

    def _run_fuzz_tool(self, tool_config: Dict) -> Set[str]:
        """(SÍNCRONO) Ejecuta una herramienta de fuzzing. Diseñado para ser llamado en un executor."""
        command = tool_config['command']
        output_file = tool_config['output_file']
        output_parser = tool_config['output_parser']
        try:
            # ANOTACIÓN: Un timeout generoso para herramientas que pueden tardar.
            result = run_tool(command, timeout=900)
            if result["returncode"] == 0 and Path(output_file).exists():
                return output_parser(output_file)
            log.warning(f"La herramienta {command[0]} finalizó con código {result['returncode']} o no generó salida para el host {command[2]}. Stderr: {result['stderr'][:200]}")
        except Exception as e:
            log.error(f"Excepción al ejecutar {command[0]}: {e}")
        return set()

    # --- Métodos de parseo de salida de herramientas ---
    def _parse_ffuf_output(self, output_file: str) -> Set[str]:
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return {item['url'] for item in data.get('results', [])}
        except (json.JSONDecodeError, IOError, KeyError) as e:
            log.error(f"Error parseando la salida de ffuf {output_file}: {e}")
        return set()
    
    def _parse_dirsearch_output(self, output_file: str) -> Set[str]:
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                # Dirsearch reporta un JSON por línea
                return {json.loads(line)['url'] for line in f if line.strip()}
        except (json.JSONDecodeError, IOError, KeyError) as e:
            log.error(f"Error parseando la salida de dirsearch {output_file}: {e}")
        return set()

    def _parse_arjun_output(self, output_file: str) -> Set[str]:
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # Arjun devuelve una estructura anidada con los parámetros.
            params = set()
            for host_data in data.values():
                params.update(host_data.get("params", {}).keys())
            return params
        except (json.JSONDecodeError, IOError, KeyError) as e:
            log.error(f"Error parseando la salida de arjun {output_file}: {e}")
        return set()
        
    def _fuzz_parameters(self, host: str, found_params: Set[str]) -> Set[str]:
        """Genera URLs completas con parámetros descubiertos y parámetros comunes."""
        base_url = f"https://{host}/"
        all_params = found_params.union(set(self.fuzz_params))
        endpoints = set()
        for param in all_params:
            endpoints.add(f"{base_url}?{param}=FUZZ")
        return endpoints

    # -------------------------------------------------------------------------
    # MÉTODOS DE ANÁLISIS DE VULNERABILIDADES
    # -------------------------------------------------------------------------
    
    async def _test_injection(self, session: aiohttp.ClientSession, host: str, endpoints: List[str], payloads: Set[str], injection_type: str):
        """Prueba inyecciones genéricas (SQLi, LFI, etc.) de forma asíncrona."""
        if not payloads:
            log.warning(f"No hay payloads cargados para el análisis de {injection_type} en {host}. Saltando.")
            return

        tasks = []
        payloads_sample = random.sample(list(payloads), min(30, len(payloads)))
        
        for endpoint in endpoints:
            parsed = urllib.parse.urlparse(endpoint)
            # Solo probamos endpoints con el placeholder FUZZ que indica un punto de inyección.
            if "FUZZ" not in parsed.query:
                continue

            query_params = urllib.parse.parse_qs(parsed.query)
            for param, values in query_params.items():
                if "FUZZ" in values:
                    for payload in payloads_sample:
                        # Reemplaza FUZZ con el payload
                        new_query = query_params.copy()
                        new_query[param] = payload
                        # `doseq=True` es importante para manejar múltiples valores por parámetro
                        new_url = parsed._replace(query=urllib.parse.urlencode(new_query, doseq=True)).geturl()
                        
                        tasks.append(self._execute_request(
                            session, host, new_url, payload, self.session_headers.copy(), injection_type
                        ))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # --- Puntos de entrada para cada tipo de análisis ---
    
    async def perform_xss_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        log.info(f"Analizando XSS en {host}...")
        tasks = [self._test_xss_on_endpoint(session, host, endpoint) for endpoint in endpoints if "FUZZ" in endpoint]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def perform_sqli_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        log.info(f"Analizando SQLi en {host}...")
        await self._test_injection(session, host, endpoints, self.sqli_payloads, "SQLi")

    async def perform_lfi_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        log.info(f"Analizando LFI en {host}...")
        await self._test_injection(session, host, endpoints, self.lfi_payloads, "LFI")

    async def perform_cmd_injection_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        log.info(f"Analizando Inyección de Comandos en {host}...")
        await self._test_injection(session, host, endpoints, self.cmd_injection_payloads, "Command Injection")

    async def perform_crlf_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        log.info(f"Analizando CRLF en {host}...")
        await self._test_injection(session, host, endpoints, self.crlf_payloads, "CRLF Injection")

    async def perform_upload_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        log.info(f"Analizando puntos de carga de archivos en {host}...")
        upload_endpoints = [ep for ep in endpoints if any(k in ep.lower() for k in ['upload', 'file', 'attach'])]
        if not upload_endpoints: return

        files_to_test = self.wordlists.get('flash', []) + self.wordlists.get('antivirus', [])
        tasks = []
        for endpoint in upload_endpoints:
            for file_path in files_to_test:
                tasks.append(self._test_file_upload(session, host, endpoint, file_path))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            
    # -------------------------------------------------------------------------
    # MÉTODOS DE TESTEO ESPECIALIZADOS
    # -------------------------------------------------------------------------

    async def _test_xss_on_endpoint(self, session: aiohttp.ClientSession, host: str, endpoint: str):
        """(Worker) Prueba un único endpoint para múltiples vectores XSS."""
        cache_key = f"xss_{endpoint}"
        if cache_key in self.cache: return

        async with self.semaphore:
            parsed = urllib.parse.urlparse(endpoint)
            query_params = urllib.parse.parse_qs(parsed.query)
            payloads_sample = random.sample(list(self.xss_payloads), min(10, len(self.xss_payloads)))

            for param, values in query_params.items():
                if "FUZZ" not in values: continue
                
                for payload in payloads_sample:
                    tasks = [
                        self._test_reflected_xss(session, host, endpoint, param, payload),
                        self._test_dom_xss(host, endpoint, param, payload),
                        self._test_post_xss(session, host, endpoint, param, payload)
                    ]
                    await asyncio.gather(*tasks, return_exceptions=True)
            
            self.cache[cache_key] = True

    def _build_url_with_payload(self, base_endpoint: str, param: str, payload: str) -> str:
        """Construye una URL reemplazando el placeholder FUZZ con un payload."""
        parsed = urllib.parse.urlparse(base_endpoint)
        query = urllib.parse.parse_qs(parsed.query)
        query[param] = payload
        return parsed._replace(query=urllib.parse.urlencode(query, doseq=True)).geturl()
    
    async def _test_reflected_xss(self, session: aiohttp.ClientSession, host: str, endpoint: str, param: str, payload: str):
        new_url = self._build_url_with_payload(endpoint, param, payload)
        await self._execute_request(session, host, new_url, payload, self.session_headers.copy(), "XSS Reflejado")
    
    async def _test_post_xss(self, session: aiohttp.ClientSession, host: str, endpoint: str, param: str, payload: str):
        data = {param: payload}
        headers = self.session_headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        # El endpoint para POST podría no tener query string.
        clean_url = urllib.parse.urlparse(endpoint)._replace(query='').geturl()
        await self._execute_request(session, host, clean_url, payload, headers, "XSS (POST)", method='POST', data=data)

    async def _test_dom_xss(self, host: str, endpoint: str, param: str, payload: str):
        """Usa Selenium para detectar DOM XSS, ejecutándolo en un hilo para no bloquear."""
        if not self.selenium_driver: return

        new_url = self._build_url_with_payload(endpoint, param, payload)
        
        loop = asyncio.get_running_loop()
        try:
            # CORRECCIÓN: La acción de Selenium (bloqueante) se ejecuta en el executor.
            is_vulnerable = await loop.run_in_executor(self.executor, self._run_selenium_check, new_url)
            if is_vulnerable:
                await self._save_finding(host, new_url, f"Posible DOM XSS detectado con Selenium en parámetro '{param}'", "DOM XSS", 7.5)
        except Exception as e:
            log.error(f"Error en test de Selenium para {new_url}: {e}")

    def _run_selenium_check(self, url: str) -> bool:
        """(SÍNCRONO) Acción de Selenium para ser ejecutada en un hilo."""
        try:
            self.selenium_driver.get(url)
            # ANOTACIÓN: La forma más simple de verificar un XSS es manejar una alerta.
            alert = self.selenium_driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            # Si se pudo manejar una alerta, es una fuerte indicación de XSS.
            log.info(f"Alerta de Selenium capturada en {url} con texto: {alert_text}")
            return True
        except Exception:
            # Es normal que no haya una alerta, por eso no se registra como error.
            return False

    async def _test_file_upload(self, session: aiohttp.ClientSession, host: str, endpoint: str, file_path: Path):
        """Prueba la carga de archivos maliciosos."""
        async with self.semaphore:
            try:
                data = aiohttp.FormData()
                with open(file_path, 'rb') as f:
                    data.add_field('file', f, filename=file_path.name, content_type='application/octet-stream')
                
                async with session.post(endpoint, data=data, timeout=20) as response:
                    text = await response.text()
                    if response.status < 400 and "success" in text.lower():
                        await self._save_finding(host, endpoint, f"Carga de archivo '{file_path.name}' parece exitosa.", "File Upload", 7.0)
            except Exception as e:
                log.error(f"Error probando upload en {endpoint} con archivo {file_path.name}: {e}")
    
    # -------------------------------------------------------------------------
    # EJECUTOR DE SOLICITUDES Y GUARDADO DE HALLAZGOS
    # -------------------------------------------------------------------------
    
    async def _execute_request(self, session: aiohttp.ClientSession, host: str, url: str, payload: str, headers: Dict, vuln_type: str, method: str = 'GET', data: Optional[Dict] = None):
        """Ejecuta una solicitud HTTP y verifica la respuesta buscando indicios de vulnerabilidad."""
        async with self.semaphore:
            try:
                proxy = self._get_random_proxy()
                kwargs = {'headers': headers, 'proxy': proxy, 'timeout': 15, 'allow_redirects': False}
                if data:
                    kwargs['data'] = data

                async with session.request(method, url, **kwargs) as response:
                    text = await response.text()
                    
                    is_vulnerable = False
                    description = f"Posible {vuln_type} en {url} con payload: {payload}"
                    
                    # Verificación para XSS
                    if "XSS" in vuln_type:
                        if payload in text and "<script>" not in text: # Evitar falsos positivos de páginas de error
                             is_vulnerable = True
                    
                    # Verificación para inyecciones basadas en errores
                    error_patterns = {
                        "SQLi": ["sql syntax", "mysql", "unclosed quotation mark", "odbc"],
                        "LFI": ["root:x:0:0", "failed to open stream", "include("],
                        "Command Injection": ["uid=", "gid=", "www-data", "root"],
                    }
                    if vuln_type in error_patterns:
                        if any(p in text.lower() for p in error_patterns[vuln_type]):
                            is_vulnerable = True

                    # Verificación para CRLF
                    if vuln_type == "CRLF Injection":
                        if "Set-Cookie:crlf-test=true" in response.headers:
                            is_vulnerable = True
                    
                    if is_vulnerable:
                        severity_map = {"SQLi": 9.0, "LFI": 8.5, "Command Injection": 9.5, "CRLF Injection": 6.5, "XSS": 7.5}
                        await self._save_finding(host, url, description, vuln_type, severity_map.get(vuln_type, 5.0))

            except asyncio.TimeoutError:
                log.warning(f"Timeout en {url} ({vuln_type})")
            except Exception as e:
                log.error(f"Error en solicitud a {url} ({vuln_type}): {e}")

    async def _save_finding(self, host: str, url: str, description: str, vuln_type: str, risk_score: float, cve: Optional[str] = None):
        """Guarda un hallazgo en la base de datos de forma asíncrona."""
        try:
            # CORRECCIÓN: Asegurarse de usar `await` para los métodos asíncronos de la BD.
            finding_id = await self.db.insert_finding_async(self.program_name, host, url, description, vuln_type, risk_score, cve)
            log.info(f"✅ Hallazgo guardado (ID:{finding_id}): [{vuln_type}] en {host} | Score: {risk_score}")
        except Exception as e:
            log.error(f"Error al guardar hallazgo para {host}: {e}")

    # -------------------------------------------------------------------------
    # GENERACIÓN DE REPORTES Y UTILIDADES
    # -------------------------------------------------------------------------

    async def _generate_report(self):
        """Genera reportes en JSON y Markdown a partir de los hallazgos en la BD."""
        log.info("Generando reportes finales...")
        try:
            findings = await self.db.fetch_all_async(
                "SELECT * FROM findings WHERE program_name = ? ORDER BY risk_score DESC",
                (self.program_name,)
            )
            if not findings:
                log.info("No se encontraron nuevos hallazgos para generar reporte.")
                return

            report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_data = {
                "program_name": self.program_name,
                "generated_at": datetime.utcnow().isoformat(),
                "findings_count": len(findings),
                "findings": [dict(finding) for finding in findings] # Convertir Row a dict
            }
            
            os.makedirs(REPORT_DIR, exist_ok=True)
            
            # Guardar reporte JSON
            json_path = REPORT_DIR / f"{self.program_name}_report_{report_time}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            await self.db.insert_report_async(self.program_name, "JSON", str(json_path))

            # Guardar reporte Markdown
            md_path = REPORT_DIR / f"{self.program_name}_report_{report_time}.md"
            with open(md_path, 'w', encoding='utf-8') as f:
                f.write(f"# Reporte de Vulnerabilidades - {self.program_name}\n\n")
                f.write(f"**Generado el:** {report_data['generated_at']} UTC\n\n")
                f.write(f"**Total de hallazgos:** {len(findings)}\n\n---\n\n")
                for finding in findings:
                    f.write(f"### 🔴 {finding['vuln_type']} (Score: {finding['risk_score']})\n\n")
                    f.write(f"- **Host:** `{finding['target']}`\n")
                    f.write(f"- **URL Vulnerable:** `{finding['url']}`\n")
                    f.write(f"- **Descripción:** {finding['description']}\n")
                    f.write(f"- **CVE Asociado:** {finding['cve'] or 'N/A'}\n")
                    f.write(f"- **Estado:** {finding['status']}\n")
                    f.write(f"- **Detectado el:** {finding['timestamp']}\n\n---\n")

            await self.db.insert_report_async(self.program_name, "Markdown", str(md_path))
            log.info(f"Reportes generados exitosamente en: {REPORT_DIR}")
        
        except Exception as e:
            log.error(f"Error crítico al generar reportes: {e}", exc_info=True)


    def _get_random_user_agent(self) -> str:
        """Obtiene un user-agent aleatorio de la lista precargada."""
        return random.choice(self.user_agents)

    def _get_random_proxy(self) -> Optional[str]:
        """Obtiene un proxy aleatorio de la lista precargada."""
        return random.choice(self.proxies) if self.proxies else None
