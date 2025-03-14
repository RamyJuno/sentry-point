# core/controller.py

from core.config import ConfigManager
from core.logger import setup_logger
from core.report import ReportGenerator

# Import modules
from modules.subdomain_enum import SubdomainEnum
from modules.dns_analysis import DNSAnalysis
from modules.masscan_scanner import MasscanScanner
from modules.waf_detector import WAFDetector
from modules.web_scanner import WebScanner
from modules.vuln_scanner import VulnScanner
from modules.breach_lookup import BreachLookup
from modules.ssl_scanner import SSLScanner
from modules.nmap_scanner import NmapScanner

class Controller:
    def __init__(self, config_path="config/settings.yaml"):
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load_config()
        self.logger = setup_logger("Controller")
        self.report = ReportGenerator()

        # Initialize modules
        self.modules = []
        self._load_modules()

    def _load_modules(self):
        """
        Dynamically load or conditionally load modules based on config.
        The order here is important: subdomain enum -> DNS -> masscan -> WAF -> ...
        """
        # Subdomain Enumeration
        self.modules.append(SubdomainEnum(self.config))

        # DNS Analysis
        self.modules.append(DNSAnalysis(self.config))

        # Masscan-based Port Scanning
        self.modules.append(MasscanScanner(self.config))
        
        # Nmap-based port scanning
        self.modules.append(NmapScanner(self.config))

        # WAF Detection
        if self.config.get("waf_detector", {}).get("enabled", False):
            self.modules.append(WAFDetector(self.config))

        # SSL Scanner
        if self.config.get("ssl_scanner", {}).get("enabled", False):
            self.modules.append(SSLScanner(self.config))

        # Web Scanner
        if self.config.get("web_scanner", {}).get("enabled", False):
            self.modules.append(WebScanner(self.config))

        # Vulnerability Scanner
        if self.config.get("vuln_scanner", {}).get("enabled", False):
            self.modules.append(VulnScanner(self.config))

        # Breach Lookup
        if self.config.get("breach_lookup", {}).get("enabled", False):
            self.modules.append(BreachLookup(self.config))

        self.logger.info("Modules loaded: %s", [mod.__class__.__name__ for mod in self.modules])

    def run(self, targets):
        """
        Executes modules in sequence, collecting data.
        """
        self.logger.info("Starting Controller run...")
        gathered_info = {}
        gathered_info["targets"] = targets

        for module in self.modules:
            module_name = module.__class__.__name__
            self.logger.info(f"Running module: {module_name}")
            try:
                result = module.run(targets, gathered_info)
                if result:
                    gathered_info[module_name] = result
            except Exception as e:
                self.logger.error(f"Error in {module_name}: {str(e)}")

        # Generate final report
        self.report.generate(gathered_info, targets)
        self.logger.info("Controller run completed.")
