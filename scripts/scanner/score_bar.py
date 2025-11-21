class ScoreBar:
    def __init__(self, score):
        self.score = score
        self.length = 20
    

    def display_bar(self):
        filled = int(self.score * self.length / 100)
        empty = self.length - filled
        return "[" + "#" * filled + "-" * empty + f"] {self.score:.0f}%"

