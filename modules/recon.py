# modules/recon.py
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from utils.tool_wrapper import run_tool, is_tool_available
from modules.database import Database
import psutil

log = logging.getLogger(__name__)

class ReconModule:
    def __init__(self):
        self.db = Database()
        self.max_workers = min(10, psutil.cpu_count(logical=True) * 2)  # Dinámico según CPU
        self.cache_dir = "output/recon_cache"
        self.required_tools = ["amass", "subfinder", "assetfinder", "findomain", "dnsx", "httpx", "waybackurls", "gau", "katana"]

    def run(self, program_name: str):
        log.info(f"Iniciando Reconocimiento para {program_name}...")
        os.makedirs(self.cache_dir, exist_ok=True)

        # Verificar herramientas
        missing_tools = [tool for tool in self.required_tools if not is_tool_available(tool)]
        if missing_tools:
            log.error(f"Herramientas faltantes: {', '.join(missing_tools)}. Instálalas antes de continuar.")
            return [], []

        program = self.db.fetch_one("SELECT scope FROM programs WHERE name = ?", (program_name,))
        domains = program['scope'].split(',') if program else ["myntra.com"]

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            subdomain_lists = []
            futures = [executor.submit(self.enumerate_subdomains, (program_name, domain)) for domain in domains]
            for future in futures:
                try:
                    subdomain_lists.append(future.result())
                except Exception as e:
                    log.error(f"Error en enumeración de subdominios: {e}")

        subdomains = set(sub for sublist in subdomain_lists for sub in sublist)
        live_hosts = self.find_live_hosts(subdomains)
        endpoints = []
        for host in live_hosts:
            endpoints.extend(self.discover_endpoints(host))

        return list(live_hosts), endpoints

    def enumerate_subdomains(self, args):
        program_name, domain = args
        log.info(f"Enumerando subdominios para {domain}...")
        cache_file = f"{self.cache_dir}/{program_name}_{domain}_subdomains.txt"
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]

        subdomains = set()
        tools = [
            {"tool": "amass", "command": ["amass", "enum", "-passive", "-d", domain], "output_file": f"output/{program_name}_{domain}_amass.txt"},
            {"tool": "subfinder", "command": ["subfinder", "-d", domain, "-silent"], "output_file": f"output/{program_name}_{domain}_subfinder.txt"},
            {"tool": "assetfinder", "command": ["assetfinder", "--subs-only", domain], "output_file": f"output/{program_name}_{domain}_assetfinder.txt"},
            {"tool": "findomain", "command": ["findomain", "-t", domain, "--quiet"], "output_file": f"output/{program_name}_{domain}_findomain.txt"},
            {"tool": "dnsx", "command": ["dnsx", "-d", domain, "-silent"], "output_file": f"output/{program_name}_{domain}_dnsx.txt"}
        ]

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self._run_tool, tool) for tool in tools]
            for future in futures:
                try:
                    subdomains.update(future.result())
                except Exception as e:
                    log.error(f"Error ejecutando herramienta: {e}")

        with open(cache_file, 'w') as f:
            for sub in subdomains:
                f.write(f"{sub}\n")
        return list(subdomains)

    def _run_tool(self, tool_config):
        command = tool_config['command']
        output_file = tool_config['output_file']
        subdomains = set()
        try:
            result = run_tool(command, output_file=output_file)
            if result["returncode"] == 0 and os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        sub = line.strip()
                        if sub:
                            subdomains.add(sub)
            else:
                log.warning(f"Fallo en {command[0]}: {result['stderr']}")
        except Exception as e:
            log.error(f"Error ejecutando {command[0]}: {e}")
        return subdomains

    def discover_endpoints(self, host):
        log.info(f"Buscando endpoints para {host}...")
        cache_file = f"{self.cache_dir}/{host}_endpoints.txt"
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]

        endpoints = set()
        tools = [
            {"tool": "waybackurls", "command": ["waybackurls", host], "output_file": f"output/{host}_wayback.txt"},
            {"tool": "gau", "command": ["gau", host], "output_file": f"output/{host}_gau.txt"},
            {"tool": "katana", "command": ["katana", "-u", f"https://{host}", "-silent"], "output_file": f"output/{host}_katana.txt"}
        ]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(self._run_tool, tool) for tool in tools]
            for future in futures:
                try:
                    endpoints.update(future.result())
                except Exception as e:
                    log.error(f"Error descubriendo endpoints: {e}")

        with open(cache_file, 'w') as f:
            for ep in endpoints:
                f.write(f"{ep}\n")
        return list(endpoints)

    def find_live_hosts(self, subdomains: set) -> list:
        log.info("Buscando hosts vivos con httpx...")
        cache_file = f"{self.cache_dir}/live_hosts.txt"
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]

        live_hosts = set()
        temp_file = "output/subdomains_temp.txt"
        with open(temp_file, 'w') as f:
            f.write('\n'.join(subdomains) + '\n')

        command = ["httpx", "-l", temp_file, "-silent", "-status-code", "-title"]
        try:
            result = run_tool(command, output_file="output/live_hosts.txt")
            if result["returncode"] == 0:
                for line in result["stdout"].splitlines():
                    if line.strip():
                        live_hosts.add(line.split()[0])
            else:
                log.warning(f"Fallo en httpx: {result['stderr']}")
        except Exception as e:
            log.error(f"Error ejecutando httpx: {e}")

        with open(cache_file, 'w') as f:
            for host in live_hosts:
                f.write(f"{host}\n")
        return list(live_hosts)
