# modules/waf_detector.py

import requests

class WAFDetector:
    """
    Basic WAF detection by analyzing HTTP responses or known server headers.
    In reality, you might integrate a library like 'wafw00f' or do more advanced checks.
    """
    def __init__(self, config):
        self.config = config

    def run(self, targets, context):
        results = {}
        masscan_data = context.get("MasscanScanner", {})

        for target, scan_info in masscan_data.items():
            ip = scan_info.get("resolved_ip")
            open_ports = scan_info.get("open_ports", [])
            waf_found = False
            waf_details = ""

            # We check for common HTTP ports, but you could check all open ports
            for port in open_ports:
                if port in [80, 443, 8080, 8443]:
                    protocol = "https" if port in [443, 8443] else "http"
                    url = f"{protocol}://{target}:{port}"
                    # Basic detection attempt
                    try:
                        resp = requests.get(url, timeout=3, verify=False)
                        # Checking typical Cloudflare or WAF headers
                        if "cloudflare" in resp.headers.get("Server", "").lower():
                            waf_found = True
                            waf_details = "Cloudflare"
                        elif "akamai" in resp.headers.get("Server", "").lower():
                            waf_found = True
                            waf_details = "Akamai"
                        # Add more checks as needed...
                        if waf_found:
                            break
                    except:
                        pass
            results[target] = {
                "waf_detected": waf_found,
                "waf_details": waf_details
            }
        return results
