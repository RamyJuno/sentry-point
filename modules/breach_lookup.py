# modules/breach_lookup.py

import requests
from core.data_types import BreachRecord

class BreachLookup:
    """
    Looks up potential leaked credentials for domain-based emails using a chosen provider.
    Examples: DeHashed, HaveIBeenPwned, etc.
    """
    def __init__(self, config):
        self.config = config
        self.enabled = self.config.get("breach_lookup", {}).get("enabled", False)
        self.provider = self.config.get("breach_lookup", {}).get("provider", "")
        self.api_key = self.config.get("breach_lookup", {}).get("api_key", "")
        self.api_secret = self.config.get("breach_lookup", {}).get("api_secret", "")

    def run(self, targets, context):
        if not self.enabled:
            return {}

        subdomains_data = context.get("SubdomainEnum", {})
        results = {}

        # For each domain, guess some possible emails, or gather from other modules
        for domain in targets:
            if self._is_ip(domain):
                continue
            emails = self._generate_emails(domain)
            # you could also parse from subdomains, or from open services
            for email in emails:
                breaches = self._lookup_breaches(email)
                if breaches:
                    results[email] = [b.__dict__ for b in breaches]

        return results

    def _generate_emails(self, domain):
        # Very naive approach. In real usage, gather from LinkedIn, Hunter.io, etc.
        return [
            f"admin@{domain}",
            f"info@{domain}",
            f"hr@{domain}"
        ]

    def _lookup_breaches(self, email):
        """
        Dummy approach. Replace with real provider calls.
        E.g., DeHashed: https://www.dehashed.com/docs
        """
        # Check for presence in a "breached" dummy list
        if "admin@" in email:
            return [
                BreachRecord(
                    email=email,
                    breach_name="DummyBreach",
                    date="2022-01-01",
                    exposed_data="Password123"
                )
            ]
        return []

    def _is_ip(self, address):
        parts = address.split('.')
        if len(parts) == 4:
            for p in parts:
                if not p.isdigit() or not 0 <= int(p) <= 255:
                    return False
            return True
        return False
