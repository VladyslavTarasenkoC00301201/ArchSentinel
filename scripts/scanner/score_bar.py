class ScoreBar:
    def __init__(self, score):
        self.score = score
        self.length = 20
    

    def display_bar(self):
        filled = int(self.score * self.lenght / 100)
        empty = length - filled
        return "[" + "#" * filled + "-" * empty + f"] {self.percent:.0f}%"

