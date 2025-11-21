from scan_results import ScanResult




class Score:
    def __init__(self, ok: int = 0, total: int = 0):
        self.ok = ok # number of secure configurations
        self.total = total # total number of checked configurations
        self.percents = 0 


    def add_ok(self):
        self.ok += 1
        self.total +=1


    def add_total(self):
        self.total += 1

    
    def calculate_score(self): 
        if self.total == 0: 
            return 0 
        self.percents == (self.ok /self.total) * 100 
        return self.percents


    def evaluate_results(self, results: list[ScanResult]): 
        for result in results: 
            if resutl.status == "OK": 
                self.add_ok() 
            self.add_total()

            
    def merge(self, other: "Score"): # used by ScanManager to produce sum of scores of different config scans ("Score" - forward referencing)
        self.ok += other.ok
        self.total += other.total

    
    #getters
    def get_ok(self):
        return self.ok


    def get_total(self):
        return self.total
