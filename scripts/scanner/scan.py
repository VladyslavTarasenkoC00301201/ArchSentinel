from .scan_results import ScanResult
from .parsed_config import ParsedConfig
from .score import Score




class Scan:
    def __init__(self, config_path, rules, scan_name):
        self.scan_name = scan_name
        self.scan_results: list[ScanResult] = []
        self.score = Score()
        self.config_path = config_path # path to config file
        self.rules = rules # rules to be used for checks, located in rules.py
        self.parsed_config = ParsedConfig(config_path).read_config()
   

    def update_score(self):
        self.score.evaluate_results(self.scan_results)
        self.score.calculate_score()


    def get_scan_results(self):
        return self.scan_results


    def get_score(self):
        return self.score


    def run_checks(self):   # compares the configurations with the rules and updates scan_results
        for key, rule in self.rules.items():
            expected = rule["expected"]
            description = rule["description"]

            current = self.parsed_config.get(key)

            if current is None:
                status = "MISSING"
            elif current.lower() == expected.lower():
                status = "OK"
            else:
                status = "BAD"

            self.scan_results.append(
                    ScanResult(
                        key=key,
                        current=current,
                        expected=expected,
                        status=status,
                        description=description,
                        )
            )

