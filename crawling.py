import logging
from utils.tool_wrapper import run_tool

log = logging.getLogger(__name__)

class CrawlingModule:
    def run(self, live_hosts):
        log.info("Iniciando crawling profundo...")
        for host in live_hosts:
            output_file = f"output/{host}_crawl.txt"
            run_tool(["katana", "-u", host, "-o", output_file])
        return live_hosts
