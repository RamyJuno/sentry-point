# modules/dns_analysis.py

import dns.resolver

class DNSAnalysis:
    """
    Performs DNS record lookups (A, NS, MX, TXT) as configured.
    """
    def __init__(self, config):
        self.config = config
        self.check_mx = self.config.get("dns_analysis", {}).get("check_mx", True)
        self.check_ns = self.config.get("dns_analysis", {}).get("check_ns", True)
        self.check_txt = self.config.get("dns_analysis", {}).get("check_txt", True)

    def run(self, targets, context):
        results = {}

        # Also handle subdomains from SubdomainEnum if they exist
        subdomains_data = context.get("SubdomainEnum", {})

        # Combine direct domains + subdomains
        for target in targets:
            if not self._is_ip(target):
                self._analyze_domain(target, results)

            # If subdomains found, analyze them too
            subdomains = subdomains_data.get(target, [])
            for sub in subdomains:
                self._analyze_domain(sub, results)

        return results

    def _analyze_domain(self, domain, results):
        domain_info = {}
        if self.check_mx:
            domain_info["MX"] = self._dns_query(domain, "MX")
        if self.check_ns:
            domain_info["NS"] = self._dns_query(domain, "NS")
        if self.check_txt:
            domain_info["TXT"] = self._dns_query(domain, "TXT")

        results[domain] = domain_info

    def _dns_query(self, domain, record_type):
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=3)
            return [str(rdata.to_text()) for rdata in answers]
        except Exception:
            return []

    def _is_ip(self, target):
        parts = target.split('.')
        if len(parts) == 4:
            for p in parts:
                if not p.isdigit() or not 0 <= int(p) <= 255:
                    return False
            return True
        return False
