from .score_bar import ScoreBar




class ResultDisplayer:
    def __init__(self, results):
        self.results = results


    def display_results(self):
        for result in self.results:
            print(f"{result.key}: {colorize{result.status}} (expectec={result.expected}, current={result.current})")


    def colorize(status):
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        RESET = "\033[0m"

        if status == "OK":
            return GREEN + status + RESET
        elif status == "BAD":
            return RED + status + RESET
        else:
            return YELLOW + status + RESET


        def display_scan_results(self, scan):
        print(f"\n=== Scan results for {scan.scan_name} ===")
        
        for result in scan.scan_results:
            coloured_status = self.colorize(result.status)
            print(f"{result.key}: {coloured_status} "
                  f"(expected={result.expected}, current={result.current})")

        print(f"Score: {scan.score.percent:.0f}%")
        score_bar = ScoreBar(scan.score.percents)
        print(score_bar.display_bar())
    

    def display_all_scans(self, scans):
        for scan in scans:
            self.display_scan_results(scan)


    def display_overall_score(self, score):
        print("\n=== OVERALL SYSTEM SECURITY SCORE ===")
        print(f"{score.percent:.0f}%")
        print(ScoreBar(score.percents).display_bar())
