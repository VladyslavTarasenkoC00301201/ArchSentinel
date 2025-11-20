class ResultDisplayer:
    def __init__(self, results):
        self.results = results


    def display_results(self):
        for result in self.results:
            print(f"{r.key}: {r.status} (expectec={result.expected}, current={result.current})")
