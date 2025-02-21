# modules/masscan_scanner.py

import subprocess
import re
import socket

class MasscanScanner:
    """
    Uses masscan to scan ports, then parses the output.
    """
    def __init__(self, config):
        self.config = config
        scan_conf = self.config.get("scanning", {})
        self.masscan_bin = scan_conf.get("masscan_binary", "masscan")
        self.rate = scan_conf.get("rate", 100)
        self.ports = scan_conf.get("ports", "1-1000")
        self.output_file = scan_conf.get("output_file", "masscan_results.txt")
        self.additional_args = scan_conf.get("additional_args", "")

    def run(self, targets, context):
        """
        For each target (IP or domain), run masscan, parse output, and store open ports.
        """
        results = {}
        all_targets = []

        # Combine top-level targets + subdomains from SubdomainEnum
        subdomains_data = context.get("SubdomainEnum", {})
        for t in targets:
            all_targets.append(t)
            # add subdomains
            subs = subdomains_data.get(t, [])
            all_targets.extend(subs)

        # Deduplicate
        all_targets = list(set(all_targets))

        for target in all_targets:
            ip_or_domain = self._resolve_to_ip(target)
            if not ip_or_domain:
                continue

            # Run masscan
            command = (
                f"{self.masscan_bin} {ip_or_domain} "
                f"--rate {self.rate} "
                f"-p {self.ports} "
                f"{self.additional_args} "
                f"-oG {self.output_file} "
                "--open"
            )

            try:
                subprocess.check_output(command, shell=True)
                open_ports = self._parse_masscan_output(self.output_file, ip_or_domain)
                results[target] = {
                    "resolved_ip": ip_or_domain,
                    "open_ports": open_ports
                }
            except subprocess.CalledProcessError:
                results[target] = {"error": f"Masscan failed for {target}"}

        return results

    def _parse_masscan_output(self, filepath, ip):
        """
        Parse the grepable output or normal text output from masscan to extract open ports.
        """
        open_ports = []
        try:
            with open(filepath, "r") as f:
                for line in f:
                    # Example grepable format:
                    # Host: 192.168.1.10 ()    Ports: 80/open/tcp//
                    if "Ports:" in line and ip in line:
                        # Extract port from line
                        match = re.search(r"Ports: (\d+)/open", line)
                        if match:
                            port = int(match.group(1))
                            open_ports.append(port)
        except FileNotFoundError:
            pass

        return list(set(open_ports))

    def _resolve_to_ip(self, target):
        """
        Resolve domain to IP. Return None if resolution fails or it's already an IP.
        """
        if self._is_ip(target):
            return target
        try:
            return socket.gethostbyname(target)
        except:
            return None

    def _is_ip(self, address):
        parts = address.split('.')
        if len(parts) == 4:
            for p in parts:
                if not p.isdigit() or not 0 <= int(p) <= 255:
                    return False
            return True
        return False
