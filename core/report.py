# core/report.py

import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_file="report.json"):
        self.output_file = output_file

    def generate(self, data, targets):
        """
        Save results in JSON format (or any format you like).
        """
        report_content = {
            "timestamp": datetime.now().isoformat(),
            "targets": targets,
            "results": data
        }

        with open(self.output_file, "w") as f:
            json.dump(report_content, f, indent=4)

        print(f"[+] Report saved to {self.output_file}")
