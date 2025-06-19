# modules/predict.py
import logging
import numpy as np
from scipy.stats import poisson
from modules.database import Database

log = logging.getLogger(__name__)

class PredictModule:
    def __init__(self):
        self.weights = np.random.randn(5) * 0.01  # [longitud, entropía, IPs, puertos, tecnologías]
        self.bias = 0.0
        self.lr = 0.01
        self.mnt = 7 * 3600  # 7 horas

    def sigmoid(self, x: np.ndarray) -> float:
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))

    def predict(self, features: np.ndarray) -> float:
        return self.sigmoid(np.dot(features, self.weights) + self.bias)

    def train(self, features: np.ndarray, target: float):
        pred = self.predict(features)
        error = pred - target
        grad = error * pred * (1 - pred)
        self.weights -= self.lr * grad * features
        self.bias -= self.lr * grad

    def score_finding(self, finding: dict) -> float:
        prior = 0.1
        evidence = bool(finding.get("cve"))
        likelihood = 0.8 if evidence else 0.2
        posterior = (likelihood * prior) / (likelihood * prior + (1 - likelihood) * (1 - prior))
        return posterior * 10

    def opt_time(self, num_targets: int) -> float:
        lam = self.mnt / max(num_targets, 1)
        return max(poisson.ppf(np.random.random(), lam), 3600)

    async def run(self, data: tuple) -> list:
        live_hosts, endpoints = data if isinstance(data, tuple) else ([], [])
        if not live_hosts and not endpoints:
            log.info("No se recibieron datos para predecir.")
            return []
        db = await Database()
        program = "Valve"  # Obtener dinámicamente si es necesario
        prioritized = []
        for host in live_hosts:
            features = np.array([
                len(host),
                sum(ord(c) * (i + 1) for i, c in enumerate(host)) / (len(host) or 1),
                1.0,  # IP simulada
                80,   # Puerto por defecto
                1.0   # Tecnologías simuladas
            ])
            prob = self.predict(features)
            self.train(features, 1 if prob > 0.5 else 0)
            time_est = self.opt_time(len(live_hosts) + len(endpoints))
            finding = {
                'program_name': program,
                'target': host,
                'url': f"https://{host}",
                'description': f"Priorización: prob {prob:.2f}, tiempo {time_est/3600:.2f}h",
                'vuln_type': 'Prediction',
                'risk_score': prob * 10,
                'timestamp': datetime.now().isoformat()
            }
            await db.insert_finding_async(
                program, host, f"https://{host}", finding['description'],
                'Prediction', prob * 10
            )
            prioritized.append(finding)
        for endpoint in endpoints:
            finding = {
                'program_name': program,
                'target': endpoint,
                'url': endpoint,
                'description': f"Endpoint encontrado",
                'vuln_type': 'Recon',
                'risk_score': 1.0,
                'timestamp': datetime.now().isoformat()
            }
            await db.insert_finding_async(
                program, endpoint, endpoint, finding['description'],
                'Recon', 1.0
            )
            prioritized.append(finding)
        await db.close_all()
        return prioritized
