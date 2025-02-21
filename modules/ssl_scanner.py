# modules/ssl_scanner.py

import ssl
import socket
from datetime import datetime
from core.data_types import SSLInfo

class SSLScanner:
    """
    Connects via TLS to open SSL ports and retrieves certificate info.
    """
    def __init__(self, config):
        self.config = config

    def run(self, targets, context):
        results = {}
        masscan_data = context.get("MasscanScanner", {})

        for target, scan_info in masscan_data.items():
            ip = scan_info.get("resolved_ip")
            open_ports = scan_info.get("open_ports", [])
            ssl_checks = []

            # Check for commonly used SSL ports or any you want to check
            for port in open_ports:
                # Let's assume we check if the service is likely TLS:
                if port in [443, 465, 8443, 993, 995]:
                    ssl_info = self._check_ssl_cert(ip, port)
                    if ssl_info:
                        ssl_checks.append(ssl_info.__dict__)

            if ssl_checks:
                results[target] = ssl_checks

        return results

    def _check_ssl_cert(self, host, port):
        try:
            context = ssl.create_default_context()
            conn = socket.create_connection((host, port), timeout=5)
            sock = context.wrap_socket(conn, server_hostname=host)

            cert = sock.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            subject = dict(x[0] for x in cert['subject'])
            valid_from = cert['notBefore']
            valid_to = cert['notAfter']

            # Simple logic to assign a "grade"
            if "Cloudflare" in issuer.get("organizationName", ""):
                grade = "A"
            else:
                grade = "B"

            return SSLInfo(
                issuer=str(issuer),
                subject=str(subject),
                valid_from=valid_from,
                valid_to=valid_to,
                grade=grade
            )
        except:
            return None
