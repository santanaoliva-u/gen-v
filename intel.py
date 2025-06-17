# modules/intel.py
import logging
from database import Database

log = logging.getLogger(__name__)

class IntelModule:
    def __init__(self):
        self.db = Database()

    def run(self, *args, **kwargs):
        log.info("Iniciando Fase 0: Inteligencia y Selección de Objetivos...")
        self.scrape_programs()
        self.update_tvs()
        self.generate_configs()
        return args[0] if args else None  # Pass through the target_program

    def scrape_programs(self):
        log.info("Recolectando datos de programas de bug bounty...")
        programs_data = [
            {
                'name': 'Valve',  # Change to 'Myntra' if you want a separate program
                'url': 'https://hackerone.com/myntra',  # Update to Myntra's bug bounty page
                'payment': 5000,
                'scope_size': 100,
                'activity': 1,
                'response_time': 30,
                'scope': 'payments.myntra.com,uiscoop.payzippy.com,api.myntra.com,www.myntra.com',  # Your assets
                'out_of_scope': 'admin.myntra.com'
            }
        ]
        for prog in programs_data:
            self.db.execute_query(
                "INSERT OR REPLACE INTO programs (name, url, scope, out_of_scope) VALUES (?, ?, ?, ?)",
                (prog['name'], prog['url'], prog['scope'], prog['out_of_scope'])
            )

    def update_tvs(self):
        log.warning("Cálculo de TVS NO IMPLEMENTADO.")

    def generate_configs(self):
        log.info("Generando archivos de configuración de objetivos...")
        programs = self.db.fetch_all("SELECT name, scope FROM programs")
        for prog in programs:
            scope_file = f"output/{prog['name']}_scope.txt"
            with open(scope_file, 'w') as f:
                f.write(prog['scope'])
