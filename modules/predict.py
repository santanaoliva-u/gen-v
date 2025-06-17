# modules/predict.py
import logging
import numpy as np
from database import Database

log = logging.getLogger(__name__)

class PredictModule:
    def __init__(self):
        self.db = Database()

    def score_finding(self, finding: dict) -> float:
        log.info(f"Calculando puntuación para el hallazgo: {finding.get('description')}")
        prior = 0.1  # Probabilidad a priori
        evidence = bool(finding.get("cve"))
        likelihood = 0.8 if evidence else 0.2
        posterior = (likelihood * prior) / (likelihood * prior + (1 - likelihood) * (1 - prior))
        return posterior * 10  # Escalar a 0-10

    def simulate_attack_chains(self, findings: list) -> list:
        log.info("Simulando cadenas de ataque...")
        # TODO: Usar teoría de grafos en el futuro
        return [{"chain": [f["description"]], "probability": self.score_finding(f)} for f in findings]
