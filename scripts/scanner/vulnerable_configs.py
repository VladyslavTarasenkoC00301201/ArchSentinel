import json


class VulnerableConfigs:
    def __init__(self):
        self.vulnerable_configs = [] # stores scan objects that has status "BAD" or "MISSING"


    def collect(self, scans):
        for scan in scans:
            for result in scan.scan_results:
                if result.status in ("BAD", "MISSING"):
                    self.vulnerable_configs.append({
                        "scan_name": scan.scan_name,
                        "key": result.key,
                        "current": result.current,
                        "expected": result.expected,
                        "description": result.description,
                        "status": result.status
                    })


    def get_vuln_configs(self):
        return self.vulnerable_configs


    def save_vuln_config_json(self, filename = "vuln_configs.json"):
        with open(filename, "w") as f:
            json.dump(self.vulnerable_configs, f, indent=2)
        print(f"Vulnerable configs written to {filename}")
