from .rules import ALL_RULES
from .config_paths import CONFIG_PATHS
from .scan import Scan
from .score import Score




class ScansManager:
    def __init__(self):
        self.scans = [] # holds scan objectf
        self.overall_score = Score() # total score affter scanning all the config files


    def run_scan(self, scan_name: str):
        config_file = CONFIG_PATHS.get(scan_name)
        rules = ALL_RULES.get(scan_name)
        self.run_validation(config_file, rules, scan_name) # avoid undefined error if someone passes non_existing name

        scan = Scan(config_file, rules, scan_name)

        scan.run_checks() # appends object of class ScanResult to member var scan_results[]
        scan.update_score() # stores the object of the Score class in mamber var score
        
        self.scans.append(scan)

        
    def run_validation(self, config_file, rules, scan_name):
        if config_file is None:
            raise ValueError(f"No config file for scan target '{scan_name}'")
    
        if rules is None:
          raise ValueError(f"No rules for scan target '{scan_name}'")
    

    def update_overall_score(self):
        total_score = Score()

        for scan in self.scans:
            total_score.merge(scan.score)

        total_score.calculate_score()
        self.overall_score = total_score

