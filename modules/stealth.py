# modules/stealth.py
import random
from config import CONFIG
import logging
log = logging.getLogger(__name__)
class StealthModule:
    def __init__(self):
        self.proxies = self._load_file(CONFIG["stealth"]["proxy_list_file"])
        self.user_agents = self._load_file(CONFIG["stealth"]["user_agent_list_file"])

    def _load_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def get_proxy(self) -> dict:
        if not self.proxies:
            return {}
        proxy = random.choice(self.proxies)
        return {"http": proxy, "https": proxy}

    def get_user_agent(self) -> str:
        if not self.user_agents:
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        return random.choice(self.user_agents)

    def run(self, data):
        log.info("Aplicando configuraciones de evasión...")
        return data  # Pass through the data
