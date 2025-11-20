from scan_results import ScanResult




class Scan:
    def __init__(self, config_path, rules):
        self.scan_result = ScanResult()
        self.config_path = config_path # path to config file
        self.rules = rules # rules to be used for checks, located in rules.py
    
    
