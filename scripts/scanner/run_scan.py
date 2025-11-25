from .scans_manager import ScansManager
from .result_displayer import ResultDisplayer
from .score_bar import ScoreBar
from .vulnerable_configs import VulnerableConfigs

manager = ScansManager()
#targets = ["ssh", "limits", "resolv", "login_defs", "sysctl", "rsyslog"]
targets = ["ssh"]
for target in targets:
    manager.run_scan(target)

manager.update_overall_score() # combines the scores of all of the scans into a single one

displayer = ResultDisplayer()
displayer.display_overall_score(manager.overall_score)
displayer.display_all_scans(manager.scans)

vulnerabilities = VulnerableConfigs()

vulnerabilities.collect(manager.scans)

vulnerabilities.save_vuln_config_json()


    




