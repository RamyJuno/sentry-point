# modules/web_scanner.py

import requests
import subprocess
import os
from urllib.parse import urljoin

class WebScanner:
    """
    Scans any HTTP(S) port discovered by masscan. 
    - Basic banner grabbing
    - Optionally runs directory brute force (dirsearch or similar).
    """
    def __init__(self, config):
        self.config = config
        self.dirsearch_bin = self.config.get("web_scanner", {}).get("dirsearch_binary", "")
        self.dirsearch_args = self.config.get("web_scanner", {}).get("dirsearch_args", "")
        self.user_agent = "MyAdvancedPentestTool/1.0"

    def run(self, targets, context):
        results = {}
        masscan_data = context.get("MasscanScanner", {})

        for target, scan_info in masscan_data.items():
            ip = scan_info.get("resolved_ip")
            open_ports = scan_info.get("open_ports", [])

            for port in open_ports:
                # Attempt to see if it's HTTP or HTTPS
                # We'll guess based on port:
                if port in [80, 8080]:
                    protocol = "http"
                elif port in [443, 8443]:
                    protocol = "https"
                else:
                    # We can attempt a small GET to see if it responds with a valid HTTP
                    protocol = self._guess_protocol(ip, port)

                if protocol:
                    url = f"{protocol}://{target}:{port}"
                    web_info = self._scan_web(url)
                    results[url] = web_info

                    # Run directory brute force if tool is configured
                    if self.dirsearch_bin:
                        dirsearch_output = self._run_dirsearch(url)
                        if dirsearch_output:
                            results[url]["dirsearch"] = dirsearch_output

        return results

    def _scan_web(self, url):
        result = {}
        try:
            resp = requests.get(url, headers={"User-Agent": self.user_agent}, timeout=5, verify=False)
            result["status_code"] = resp.status_code
            server = resp.headers.get("Server", "Unknown")
            result["server"] = server

            # Simple detection for directory listing, etc.
            if "Index of /" in resp.text:
                result["directory_listing"] = True
        except Exception as e:
            result["error"] = str(e)
        return result

    def _run_dirsearch(self, url):
        """
        Example: dirsearch -u https://target --some-args
        This will be a simplified approach. 
        """
        command = f"{self.dirsearch_bin} -u {url} {self.dirsearch_args}"
        output_file = f"dirsearch_{url.replace(':','_').replace('/','_')}.txt"
        command += f" -o {output_file}"

        try:
            subprocess.check_output(command, shell=True)
            # parse results
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    return f.read().splitlines()
        except subprocess.CalledProcessError:
            return None

        return None

    def _guess_protocol(self, ip, port):
        """
        Quick check to see if a port speaks HTTP or HTTPS by attempting a HEAD request:
        """
        try:
            # Try HTTP
            url_http = f"http://{ip}:{port}"
            r = requests.head(url_http, timeout=2, verify=False)
            # If we don't get an exception, it's likely HTTP
            return "http"
        except:
            pass

        try:
            # Try HTTPS
            url_https = f"https://{ip}:{port}"
            r = requests.head(url_https, timeout=2, verify=False)
            return "https"
        except:
            pass

        return None
