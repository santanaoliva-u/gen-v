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
import numpy as np
from scipy.stats import poisson
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Set, Dict, Optional
from pathlib import Path
import shutil
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Importaciones locales
from modules.tool_wrapper import run_tool
from modules.database import Database
from modules.config import BASE_DIR, BASE_WORDLIST_DIR, MAX_CONCURRENT_REQUESTS, REPORTS_DIR, LOG_DIR
import psutil

# Configurar logging
log = logging.getLogger(__name__)
os.makedirs(LOG_DIR, exist_ok=True)
handler = logging.handlers.RotatingFileHandler(
    f"{LOG_DIR}/vuln_report.log", maxBytes=10*1024*1024, backupCount=5
)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
log.addHandler(handler)
log.setLevel(logging.INFO)

class DeepFuzzXSSModule:
    def __init__(self):
        self.db = None  # Instanciar en run para soportar asincronía
        self.program_name: Optional[str] = None
        self.ngrok_url: str = self._get_ngrok_url()
        self.base_dir = Path(BASE_WORDLIST_DIR)
        self.xss_payloads: Set[str] = self._load_payloads_from_sources(self._get_xss_payload_sources(), self._process_xss_payload)
        log.info(f"Cargados {len(self.xss_payloads)} payloads XSS únicos")
        self.crlf_payloads: Set[str] = self._load_crlf_payloads()
        self.fuzz_params: List[str] = self._load_fuzz_params()
        self.user_agents: List[str] = self._load_user_agents()
        self.proxies: List[str] = self._load_proxies()
        self.max_workers: int = min(10, psutil.cpu_count(logical=True) * 2)
        self.cache_file: str = str(BASE_DIR / "output" / "xss_cache.json")
        self.cve_cache_file: str = str(BASE_DIR / "output" / "cve_cache.json")
        self.cache: Dict = self._load_cache(self.cache_file)
        self.cve_cache: Dict = self._load_cache(self.cve_cache_file)
        self.session_headers: Dict = self._initialize_headers()
        self.wordlists: Dict = self._load_wordlists()
        self.extensions: List[str] = self._load_extensions()
        self.sqli_payloads: Set[str] = self._load_payloads_from_wordlist_category('sqli', 'SQLi')
        self.lfi_payloads: Set[str] = self._load_payloads_from_wordlist_category('lfi', 'LFI')
        self.cmd_injection_payloads: Set[str] = self._load_payloads_from_wordlist_category('cmd_injection', 'Command Injection')
        self.cve_scripts: List[Dict] = self._load_cve_scripts()
        self.nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.selenium_driver: Optional[webdriver.Chrome] = self._init_selenium()
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self.tools = ['ffuf', 'dirsearch', 'arjun', 'wafw00f']
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        # Modelo predictivo
        self.weights = np.random.randn(5) * 0.01  # [params_count, endpoint_length, status_code, content_type, prior_success]
        self.bias = 0.0
        self.lr = 0.01
        self.mnt = 7 * 3600  # 7 horas

    def sigmoid(self, x: np.ndarray) -> float:
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))

    def predict_vuln_prob(self, features: np.ndarray) -> float:
        return self.sigmoid(np.dot(features, self.weights) + self.bias)

    def train_model(self, features: np.ndarray, target: float):
        pred = self.predict_vuln_prob(features)
        error = pred - target
        grad = error * pred * (1 - pred)
        self.weights -= self.lr * grad * features
        self.bias -= self.lr * grad

    def opt_time(self, num_targets: int) -> float:
        lam = self.mnt / max(num_targets, 1)
        return max(poisson.ppf(np.random.random(), lam), 3600)

    def _get_ngrok_url(self) -> str:
        try:
            payload_js_path = BASE_DIR / "modules" / "xss_server" / "public" / "payload.js"
            with open(payload_js_path, 'r') as f:
                content = f.read()
                match = re.search(r'https://[a-zA-Z0-9-]+\.ngrok-free\.app', content)
                if match:
                    log.info(f"URL de ngrok detectada: {match.group(0)}")
                    return match.group(0)
            log.warning("No se detectó URL de ngrok. Usando valor predeterminado.")
            return "https://default.ngrok-free.app"
        except Exception as e:
            log.error(f"Error obteniendo URL de ngrok: {e}. Usando valor predeterminado.")
            return "https://default.ngrok-free.app"

    def _load_payloads_from_sources(self, sources: List[Path], processor):
        payloads = set()
        for source in sources:
            if source.is_dir():
                for file in source.rglob("*.txt"):
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
        if payload and not payload.startswith('#'):
            payloads.add(payload)
            payloads.add(urllib.parse.quote(payload))
            payloads.add(urllib.parse.quote_plus(payload))
            payloads.add(f"data:text/html;base64,{base64.b64encode(payload.encode()).decode()}")

    def _get_xss_payload_sources(self) -> List[Path]:
        return [
            self.base_dir / "fuzzdb" / "attack" / "xss",
            self.base_dir / "SecLists" / "Fuzzing" / "XSS",
            self.base_dir / "SecLists" / "Fuzzing" / "Polyglots",
            self.base_dir / "PayloadsAllTheThings" / "XSS Injection",
            BASE_DIR / "xss_payloads.txt"
        ]

    def _load_crlf_payloads(self) -> Set[str]:
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
        params = set(['id', 'q', 'search', 'name', 'value', 'page', 'user', 'token', 'key', 'query', 'callback', 'url', 'redirect', 'next'])
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
            log.warning("Usando user-agent predeterminado.")
            return ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36']
        log.info(f"Cargados {len(user_agents)} user-agents.")
        return user_agents

    def _load_proxies(self) -> List[str]:
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
            'lfi': [self.base_dir / "SecLists" / "Fuzzing" / "LFI"],
            'cmd_injection': [self.base_dir / "PayloadsAllTheThings" / "Command Injection"],
            'backdoors': [self.base_dir / "SecLists" / "Web-Shells" / "backdoor-list.txt"],
            'flash': [self.base_dir / "SecLists" / "Payloads" / "Flash" / "xssproject.swf"],
            'antivirus': [self.base_dir / "SecLists" / "Payloads" / "Anti-Virus" / "eicar.com.txt"]
        }
        loaded_wordlists = {key: [p for p in paths if p.exists()] for key, paths in base_paths.items()}
        return loaded_wordlists

    def _load_extensions(self) -> List[str]:
        extensions = set()
        for path in self.wordlists.get('extensions', []):
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    extensions.update(line.strip().lstrip('.') for line in f if line.strip() and not line.startswith('#'))
            except Exception as e:
                log.error(f"Error cargando extensiones de {path}: {e}")
        return list(extensions)

    def _load_cve_scripts(self) -> List[Dict]:
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
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            return webdriver.Chrome(options=chrome_options)
        except Exception as e:
            log.error(f"Error inicializando Selenium: {e}. DOM XSS deshabilitado.")
            return None

    def _load_cache(self, cache_file: str) -> Dict:
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            log.error(f"Error cargando caché {cache_file}: {e}.")
        return {}

    def _save_cache(self, cache_file: str, data: Dict):
        try:
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)
            with open(cache_file + '.tmp', 'w') as f:
                json.dump(data, f, indent=2)
            shutil.move(cache_file + '.tmp', cache_file)
        except IOError as e:
            log.error(f"Error guardando caché {cache_file}: {e}")

    def _initialize_headers(self) -> Dict:
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
        for tool in self.tools:
            if not shutil.which(tool):
                log.error(f"Herramienta '{tool}' no encontrada en el PATH.")
                raise FileNotFoundError(f"Herramienta {tool} no encontrada.")

    async def run(self, data: tuple) -> tuple:
        try:
            self._validate_tools()
        except FileNotFoundError as e:
            log.critical(str(e))
            return ([], [])

        self.db = await Database()
        live_hosts, endpoints = data if isinstance(data, tuple) and len(data) == 2 else ([], [])
        self.program_name = "Valve"  # Obtener dinámicamente si es posible
        log.info(f"Iniciando DeepFuzz en {len(live_hosts)} hosts y {len(endpoints)} endpoints...")

        async with aiohttp.ClientSession(headers=self.session_headers) as session:
            tasks = []
            for host in live_hosts:
                features = np.array([
                    len(endpoints),  # Número de endpoints
                    len(host),      # Longitud del host
                    200,            # Código de estado simulado
                    1 if 'html' in host else 0,  # Tipo de contenido
                    self.cache.get(f"xss_{host}", 0)  # Éxito previo
                ])
                prob = self.predict_vuln_prob(features)
                self.train_model(features, 1 if prob > 0.5 else 0)
                time_est = self.opt_time(len(live_hosts) + len(endpoints))
                await self.db.insert_finding_async(
                    self.program_name, host, f"https://{host}",
                    f"Priorización: prob {prob:.2f}, tiempo {time_est/3600:.2f}h",
                    "Prediction", prob * 10
                )
                tasks.append(self._process_host(session, host, endpoints))
            results = await asyncio.gather(*tasks, return_exceptions=True)

            discovered_endpoints = set(endpoints)
            for res in results:
                if isinstance(res, list):
                    discovered_endpoints.update(res)
                elif isinstance(res, Exception):
                    log.error(f"Error procesando host: {res}")

            endpoints = list(discovered_endpoints)

        self._save_cache(self.cache_file, self.cache)
        self._save_cache(self.cve_cache_file, self.cve_cache)
        await self._generate_report()

        if self.selenium_driver:
            self.selenium_driver.quit()
        self.executor.shutdown(wait=True)
        await self.db.close_all()

        return live_hosts, endpoints

    async def _process_host(self, session: aiohttp.ClientSession, host: str, existing_endpoints: list) -> List[str]:
        log.info(f"Procesando host: {host}")
        waf_detected = await self._detect_waf(host)
        fuzzed_endpoints = await self.perform_fuzzing(host)
        all_endpoints = set(fuzzed_endpoints)
        for ep in existing_endpoints:
            if host in urllib.parse.urlparse(ep).netloc:
                all_endpoints.add(ep)
        log.info(f"Host {host}: {len(all_endpoints)} endpoints para analizar.")
        endpoints_to_scan = list(all_endpoints)

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

    async def _detect_waf(self, host: str) -> bool:
        log.info(f"Detectando WAF en {host}...")
        cmd = ["wafw00f", f"https://{host}", "-o", f"output/{host}_wafw00f.json", "--format", "json"]
        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(self.executor, lambda: run_tool(cmd))
            if result["returncode"] == 0 and Path(f"output/{host}_wafw00f.json").exists():
                with open(f"output/{host}_wafw00f.json", 'r') as f:
                    data = json.load(f)
                if data.get("firewall"):
                    log.warning(f"WAF detectado en {host}: {data['firewall']}")
                    return True
            return False
        except Exception as e:
            log.error(f"Error detectando WAF en {host}: {e}")
            return False

    async def perform_fuzzing(self, host: str) -> List[str]:
        cache_key = f"fuzz_{host}"
        if cache_key in self.cache:
            log.info(f"Resultados de fuzzing para {host} desde caché.")
            return self.cache[cache_key]

        new_endpoints = set()
        loop = asyncio.get_running_loop()
        tool_configs = []
        wordlists = self.wordlists.get('dirs', []) + self.wordlists.get('files', [])
        for wordlist_path in wordlists:
            tool_configs.extend(self._get_fuzz_tools(host, wordlist_path))

        fuzz_tasks = [loop.run_in_executor(self.executor, self._run_fuzz_tool, config) for config in tool_configs]
        for future in asyncio.as_completed(fuzz_tasks):
            try:
                result_endpoints = await future
                new_endpoints.update(result_endpoints)
            except Exception as e:
                log.error(f"Error en fuzzing: {e}")

        arjun_config = {
            'tool': 'arjun',
            'command': ["arjun", "-u", f"https://{host}", "--stable", "-oJ", str(BASE_DIR / "output" / f"{host}_arjun.json")],
            'output_file': str(BASE_DIR / "output" / f"{host}_arjun.json"),
            'output_parser': self._parse_arjun_output
        }
        try:
            param_endpoints = await loop.run_in_executor(self.executor, self._run_fuzz_tool, arjun_config)
            new_endpoints.update(self._fuzz_parameters(host, param_endpoints))
        except Exception as e:
            log.error(f"Error ejecutando arjun: {e}")

        final_endpoints = list(new_endpoints)
        self.cache[cache_key] = final_endpoints
        log.info(f"Fuzzing en {host} encontró {len(final_endpoints)} endpoints.")
        return final_endpoints

    def _get_fuzz_tools(self, host: str, wordlist: Path) -> List[Dict]:
        ext_str = ",".join(self.extensions)
        output_dir = BASE_DIR / "output"
        output_dir.mkdir(exist_ok=True)
        base_filename = f"{host.replace('.', '_')}__{wordlist.stem}"
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
        command = tool_config['command']
        output_file = tool_config['output_file']
        output_parser = tool_config['output_parser']
        try:
            result = run_tool(command, timeout=900)
            if result["returncode"] == 0 and Path(output_file).exists():
                return output_parser(output_file)
            log.warning(f"Herramienta {command[0]} falló: {result['stderr'][:200]}")
        except Exception as e:
            log.error(f"Error ejecutando {command[0]}: {e}")
        return set()

    def _parse_ffuf_output(self, output_file: str) -> Set[str]:
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return {item['url'] for item in data.get('results', [])}
        except (json.JSONDecodeError, IOError, KeyError) as e:
            log.error(f"Error parseando ffuf {output_file}: {e}")
        return set()

    def _parse_dirsearch_output(self, output_file: str) -> Set[str]:
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                return {json.loads(line)['url'] for line in f if line.strip()}
        except (json.JSONDecodeError, IOError, KeyError) as e:
            log.error(f"Error parseando dirsearch {output_file}: {e}")
        return set()

    def _parse_arjun_output(self, output_file: str) -> Set[str]:
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            params = set()
            for host_data in data.values():
                params.update(host_data.get("params", {}).keys())
            return params
        except (json.JSONDecodeError, IOError, KeyError) as e:
            log.error(f"Error parseando arjun {output_file}: {e}")
        return set()

    def _fuzz_parameters(self, host: str, found_params: Set[str]) -> Set[str]:
        base_url = f"https://{host}/"
        all_params = found_params.union(set(self.fuzz_params))
        return {f"{base_url}?{param}=FUZZ" for param in all_params}

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
        log.info(f"Analizando Command Injection en {host}...")
        await self._test_injection(session, host, endpoints, self.cmd_injection_payloads, "Command Injection")

    async def perform_crlf_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        log.info(f"Analizando CRLF en {host}...")
        await self._test_injection(session, host, endpoints, self.crlf_payloads, "CRLF Injection")

    async def perform_upload_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        log.info(f"Analizando carga de archivos en {host}...")
        upload_endpoints = [ep for ep in endpoints if any(k in ep.lower() for k in ['upload', 'file', 'attach'])]
        if not upload_endpoints:
            return
        files_to_test = self.wordlists.get('flash', []) + self.wordlists.get('antivirus', [])
        tasks = []
        for endpoint in upload_endpoints:
            for file_path in files_to_test:
                tasks.append(self._test_file_upload(session, host, endpoint, file_path))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def detect_backdoors(self, host: str):
        log.info(f"Detectando backdoors en {host}...")
        backdoor_files = self.wordlists.get('backdoors', [])
        for file_path in backdoor_files:
            cmd = ["ffuf", "-u", f"https://{host}/FUZZ", "-w", str(file_path), "-mc", "200", "-s"]
            try:
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(self.executor, lambda: run_tool(cmd))
                if result["stdout"]:
                    for line in result["stdout"].splitlines():
                        await self.db.insert_finding_async(
                            self.program_name, host, line, "Posible backdoor encontrado", "Backdoor", 8.0
                        )
            except Exception as e:
                log.error(f"Error detectando backdoors: {e}")

    async def test_cve_exploits(self, host: str):
        log.info(f"Probando exploits CVE en {host}...")
        for script in self.cve_scripts:
            cache_key = f"cve_{host}_{script['cve_id']}"
            if cache_key in self.cve_cache:
                continue
            try:
                cmd = ["python3", script['path'], "--url", f"https://{host}"]
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(self.executor, lambda: run_tool(cmd))
                if result["returncode"] == 0 and "vulnerable" in result["stdout"].lower():
                    await self.db.insert_finding_async(
                        self.program_name, host, f"https://{host}", f"Vulnerabilidad {script['cve_id']}", "CVE", 9.0, script['cve_id']
                    )
                self.cve_cache[cache_key] = True
            except Exception as e:
                log.error(f"Error ejecutando {script['cve_id']}: {e}")

    async def _test_injection(self, session: aiohttp.ClientSession, host: str, endpoints: List[str], payloads: Set[str], injection_type: str):
        if not payloads:
            log.warning(f"No hay payloads para {injection_type} en {host}.")
            return
        tasks = []
        payloads_sample = random.sample(list(payloads), min(30, len(payloads)))
        for endpoint in endpoints:
            parsed = urllib.parse.urlparse(endpoint)
            if "FUZZ" not in parsed.query:
                continue
            query_params = urllib.parse.parse_qs(parsed.query)
            for param, values in query_params.items():
                if "FUZZ" in values:
                    for payload in payloads_sample:
                        new_query = query_params.copy()
                        new_query[param] = payload
                        new_url = parsed._replace(query=urllib.parse.urlencode(new_query, doseq=True)).geturl()
                        tasks.append(self._execute_request(
                            session, host, new_url, payload, self.session_headers.copy(), injection_type
                        ))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_xss_on_endpoint(self, session: aiohttp.ClientSession, host: str, endpoint: str):
        cache_key = f"xss_{endpoint}"
        if cache_key in self.cache:
            return
        async with self.semaphore:
            parsed = urllib.parse.urlparse(endpoint)
            query_params = urllib.parse.parse_qs(parsed.query)
            payloads_sample = random.sample(list(self.xss_payloads), min(10, len(self.xss_payloads)))
            for param, values in query_params.items():
                if "FUZZ" not in values:
                    continue
                for payload in payloads_sample:
                    tasks = [
                        self._test_reflected_xss(session, host, endpoint, param, payload),
                        self._test_dom_xss(host, endpoint, param, payload),
                        self._test_post_xss(session, host, endpoint, param, payload)
                    ]
                    await asyncio.gather(*tasks, return_exceptions=True)
            self.cache[cache_key] = True

    def _build_url(self, endpoint: str, param: str, payload: str -> str:
        parsed = urllib.parse.urlparse(endpoint))
        query = urllib.parse.parse_qs(parsed.query)
        query[param] = [payload]
        return parsed._replace(query=urllib.parse.urlencode(query, doseq=True)).geturl()

    async def _test_reflected_xss_reflected_xss(self, session: aiohttp.ClientSession, host: str, endpoint: str, param: str, payload: str):
        new_url = self._build_url(self._endpoint, param, payload)
        await self._execute_request(
            session, host, new_url, payload, self._session_headers.copy(), "XSS Reflected"
        )

    async def _test_post_xss(self, session: aiohttp.ClientSession, host: str, endpoint: str, param: str, payload: str):
        data = {param: payload}
        headers = self._session_headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded']
        clean_url = urllib.parse.urlparse(endpoint).urlparse(endpoint)._replace(query='').geturl()
        await self._execute_request(
            session, host, clean_url, payload, headers, "XSS (POST)", method='POST', data=data
        )

    async def _test_dom_xss(self, _host: str, endpoint: str, _param: str, _payload: str):
        if not self._selenium_driver:
            return
        new_url = self._build_url(endpoint, _param, payload)
        loop = asyncio.get_running_loop()
        try:
                is_vulnerable = await loop.run_in_executor(
                    self.executor, lambda: self._run_selenium_check(new_url)
                if is_vulnerable:
                    await self._save_finding(
                        host, new_url, f"Posible DOM XSS en '{param}'", "DOM XSS", 7.5
                    )
            except Exception as e:
                log.error(f"f"Error en Selenium para {new_url}: {e}")
        )

    def _run_selenium_check(self, url: str) -> bool:
        try:
            self._selenium_driver.get(url)
            alert = self._selenium_driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            log.info(f"Alerta capturada en {url}: {alert_text}")
            return True
        except Exception:
            return False

    async def _test_file_upload(self, session: aiohttp.ClientSession, host: str, endpoint: str, file_path: Path):
        async with self.semaphore:
            try:
                data = aiohttp.FormData()
                with open(file_path, 'rb') as f:
                    data.add_field('file', f, filename=file_path.name, content_type='application/octet-stream')
                async with session.post(endpoint, data=data, timeout=20) as response:
                    text = await response.text()
                    if response.status < 400 and "success" in text.lower():
                        await self.db.insert_finding_async(
                            self.program_name, host, endpoint,
                            f"Carga de '{file_path.name}' exitosa.", "File Upload", 7.0
                        )
            except Exception as e:
                log.error(f"Error en upload {endpoint} con {file_path.name}: {e}")

    async def _execute_request(self, session: aiohttp.ClientSession, host: str, url: str, payload: str, headers: Dict, vuln_type: str, method: str = 'GET', data: Optional[Dict] = None):
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
                    if "XSS" in vuln_type:
                        if payload in text and "<script>" not in text:
                            is_vulnerable = True
                    error_patterns = {
                        "SQLi": ["sql syntax", "mysql", "unclosed quotation mark", "odbc"],
                        "LFI": ["root:x:0:0", "failed to open stream", "include("],
                        "Command Injection": ["uid=", "gid=", "www-data", "root"],
                    }
                    if vuln_type in error_patterns:
                        if any(p in text.lower() for p in error_patterns[vuln_type]):
                            is_vulnerable = True
                    if vuln_type == "CRLF Injection":
                        if "Set-Cookie:crlf-test=true" in response.headers:
                            is_vulnerable = True
                    if is_vulnerable:
                        severity_map = {"SQLi": 9.0, "LFI": 8.5, "Command Injection": 9.5, "CRLF Injection": 6.5, "XSS Reflected": 7.5, "XSS (POST)": 7.5, "DOM XSS": 7.5}
                        await self._save_finding(host, url, description, vuln_type, severity_map.get(vuln_type, 5.0))
            except asyncio.TimeoutError:
                log.warning(f"Timeout en {url} ({vuln_type})")
            except Exception as e:
                log.error(f"Error en {url} ({vuln_type}): {e}")

    async def _save_finding(self, host: str, url: str, description: str, vuln_type: str, risk_score: float, cve: Optional[str] = None):
        try:
            finding_id = await self.db.insert_finding_async(
                self.program_name, host, url, description, vuln_type, risk_score, cve
            )
            log.info(f"✅ Hallazgo (ID:{finding_id}): [{vuln_type}] en {host} | Score: {risk_score}")
        except Exception as e:
            log.error(f"Error guardando hallazgo para {host}: {e}")

    async def _generate_report(self):
        log.info("Generando reportes...")
        try:
            f:indings = await self.db.fetch_all_async(
                "SELECT * FROM findings WHERE program_name = ? ORDER BY risk_score DESC",
                (self.program_name,)
            )
            if not findings:
                log.info("No hay hallazgos para reportar.")
                return
            report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_data = {
                "program_name": self.program_name,
                "generated_at": datetime.utcnow().isoformat(),
                "findings_count": len(findings),
                "findings": [dict(finding) for finding in findings]
            }
            os.makedirs(REPORTS_DIR, exist_ok=True)
            json_path = REPORTS_DIR / f"{self.program_name}_report_{report_time}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            await self.db.insert_report_async(self.program_name, "JSON", str(json_path))
            md_path = REPORTS_DIR / f"{self.program_name}_report_{report_time}.md"
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
            log.info(f"Reportes generados en: {REPORTS_DIR}")
        except Exception as e:
            log.error(f"Error generando reportes: {e}", exc_info=True)

    def _get_random_user_agent(self) -> str:
        return random.choice(self.user_agents)

    def _get_random_proxy(self) -> Optional[str]:
        return random.choice(self.proxies) if self.proxies else None
