# modules/learning.py
import logging
from database import Database

log = logging.getLogger(__name__)

class LearningModule:
    def __init__(self):
        self.db = Database()

    def run(self):
        log.info("Iniciando Fase 6: Ciclo de Aprendizaje Adaptativo...")
        self.update_reputations_from_feedback()
        self.optimize_strategies()

    def update_reputations_from_feedback(self):
        findings = self.db.fetch_all("SELECT * FROM findings WHERE status IN ('ACCEPTED', 'REJECTED')")
        for finding in findings:
            template_id = finding["cve"] or "generic"
            success = finding["status"] == "ACCEPTED"
            self.db.execute_query(
                "INSERT OR REPLACE INTO template_reputation (template_id, reputation_score, success_count, fail_count) "
                "VALUES (?, COALESCE((SELECT reputation_score FROM template_reputation WHERE template_id = ?) + ?, 0.5), "
                "COALESCE((SELECT success_count FROM template_reputation WHERE template_id = ?) + ?, 0), "
                "COALESCE((SELECT fail_count FROM template_reputation WHERE template_id = ?) + ?, 0))",
                (template_id, template_id, 0.1 if success else -0.1, template_id, 1 if success else 0, template_id, 0 if success else 1)
            )

    def optimize_strategies(self):
        log.info("Optimizando estrategias basadas en reputación...")
        # TODO: Implementar Q-learning en el futuro
