


class Score:
    def __init__(self):
        self.ok = 0 # number of secure configurations
        self.total = 0 # total number of checked configurations
        self.percents = 0 




    def add_ok(self):
        self.ok += 1
        self.total +=1


    def add_fail(self):
        self.total += 1

    
    def calculate_score(self):
        if self.total == 0:
            return 0
        self.percents == (self.ok /self.total) * 100
        return self.percents


    
