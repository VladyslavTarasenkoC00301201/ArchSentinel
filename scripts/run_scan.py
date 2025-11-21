from scanner.scans_manager import ScansManager
from scanner.result_displayer import ResultDisplayer
from scanner.score_bar import ScoreBar


manager = ScansManager()
targets = ["ssh"]

for target in targets:
    manager.run_scan(target)
manager.update_overall_score()

print("\n=== OVERALL SECURITY SCORE ===")
score_bar = ScoreBar(manager.overall_score.percents)
print(score_bar.display_bar())

for scan in manager.scans:
    print(f"\n=== Results for {scan.scan_name} ===")
    for res in scan.scan_results:
        print(res.key, res.status)
    print("Score:", scan.score.percents)
    




