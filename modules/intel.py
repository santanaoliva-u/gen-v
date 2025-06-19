# modules/intel.py
import logging
from modules.database import Database

log = logging.getLogger(__name__)

class IntelModule:
    async def run(self, program_name: str) -> str:
        db = await Database()
        log.info(f"Iniciando Fase 0: Inteligencia para {program_name}...")
        await self.scrape_programs(db, program_name)
        await self.update_tvs(db)
        await self.generate_configs(db, program_name)
        await db.close_all()
        return program_name

    async def scrape_programs(self, db: Database, program_name: str):
        log.info("Recolectando datos de programas...")
        programs_data = [
            {
                'name': program_name,
                'url': f"https://hackerone.com/{program_name.lower()}",
                'scope': 'payments.value.com,api.value.com,www.value.com',
                'out_of_scope': 'admin.value.com'
            }
        ]
        for prog in programs_data:
            await db.insert_finding_async(
                prog['name'], prog['name'], prog['url'],
                f"Programa: {prog['scope']}", "Intel", 0.0
            )

    async def update_tvs(self, db: Database):
        log.warning("Cálculo de TVS NO IMPLEMENTADO.")

    async def generate_configs(self, db: Database, program_name: str):
        log.info("Generando archivos de configuración...")
        programs = await db.fetch_all_async("SELECT name, scope FROM programs")
        for prog in programs:
            if prog['name'] == program_name:
                scope_file = f"output/{prog['name']}_scope.txt"
                with open(scope_file, 'w') as f:
                    f.write(prog['scope'])
