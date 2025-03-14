# modules/nmap_scanner.py

import nmap
import socket

class NmapScanner:
    def __init__(self, config):
        self.config = config.get("scanning", {})
        self.ports = self.config.get("nmap_ports", "1-1000")
        self.arguments = self.config.get("nmap_arguments", "-sV --open")

    def run(self, targets, context):
        results = {}
        nm = nmap.PortScanner()
        
        for target in targets:
            ip = self._resolve_target(target)
            if not ip:
                continue
                
            try:
                nm.scan(ip, arguments=f"{self.arguments} -p {self.ports}")
                results[target] = self._parse_results(nm, ip)
            except Exception as e:
                results[target] = {"error": str(e)}

        return results

    def _resolve_target(self, target):
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

    def _parse_results(self, scanner, ip):
        if ip not in scanner.all_hosts():
            return {"status": "host down"}
            
        host_info = scanner[ip]
        return {
            "status": host_info.state(),
            "ports": [{
                "port": port,
                "protocol": proto,
                "service": data.get("name", "unknown"),
                "version": data.get("product", "") + " " + data.get("version", "")
            } for proto in host_info.all_protocols() 
            for port, data in host_info[proto].items()]
        }