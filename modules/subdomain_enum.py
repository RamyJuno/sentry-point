# modules/subdomain_enum.py

import subprocess
import re
import time
from typing import List

class SubdomainEnum:
    """
    Supports passive (Subfinder) or active (wordlist-based bruteforce) subdomain enumeration
    based on settings in config.
    """
    def __init__(self, config):
        self.config = config
        self.mode = self.config.get("subdomain_enum", {}).get("mode", "passive")
        self.subfinder_bin = self.config.get("subdomain_enum", {}).get("subfinder_binary", "subfinder")
        self.subfinder_args = self.config.get("subdomain_enum", {}).get("subfinder_args", "")
        self.wordlist = self.config.get("subdomain_enum", {}).get("wordlist", "")
        self.threads = self.config.get("subdomain_enum", {}).get("threads", 50)

    def run(self, targets, context):
        """
        For each domain target, find subdomains.
        """
        results = {}
        for target in targets:
            if self._is_ip(target):
                continue  # skip IP addresses

            found_subs = set()

            # Passive
            if self.mode in ("passive", "both"):
                subs = self._run_subfinder(target)
                found_subs.update(subs)

            # Active bruteforce
            if self.mode in ("active", "both"):
                subs = self._bruteforce_subdomains(target)
                found_subs.update(subs)

            results[target] = list(found_subs)
            time.sleep(1)  # simple rate limit

        return results

    def _run_subfinder(self, domain) -> List[str]:
        """
        Calls subfinder externally. 
        Example: subfinder -d example.com -silent
        """
        command = f"{self.subfinder_bin} -d {domain} {self.subfinder_args}"
        try:
            output = subprocess.check_output(command, shell=True).decode("utf-8", errors="ignore")
            subs = [line.strip() for line in output.splitlines() if line.strip()]
            return subs
        except subprocess.CalledProcessError:
            return []

    def _bruteforce_subdomains(self, domain) -> List[str]:
        """
        Dummy example of brute forcing subdomains using a wordlist.
        Real approach might spawn a DNS resolution process or use something like dnsx, gobuster, etc.
        """
        if not self.wordlist:
            return []
        found = []
        try:
            with open(self.wordlist, "r") as f:
                for line in f:
                    sub = line.strip()
                    if sub:
                        subdomain = f"{sub}.{domain}"
                        # Minimal check: see if it resolves? (requires DNS lookups or ping)
                        # For brevity, let's skip real resolution:
                        found.append(subdomain)
            return found
        except FileNotFoundError:
            return []

    def _is_ip(self, target):
        parts = target.split('.')
        if len(parts) == 4:
            for p in parts:
                if not p.isdigit() or not 0 <= int(p) <= 255:
                    return False
            return True
        return False
