import argparse

from .scans_manager import ScansManager
from .result_displayer import ResultDisplayer
from .score_bar import ScoreBar
from .vulnerable_configs import VulnerableConfigs




def parse_args():
    parser = argparse.ArgumentParser(
            description = "Run configuration security scans."
            )

    parser.add_argument(
        "--scan",
        metavar="SCAN_NAME",
        help=(
            "Run a specific scan(e.g ssh, login_defs, sysctl, resolv, rsyslog, limits). "
            "If not provided, you must use --scan-all."
            ),
    )

    parser.add_argument(
        "--scan-all",
        action="store_true",
        help="Run all available scans.",
    )
    
    parser.add_argument(
        "-j",
        "--json",
        metavar="FILE",
        nargs="?",  # number of arguments - defines an optional number of arguments (can be 0)
        const="vuln_configs.json",
        help="Save BAD/MISSING findings to JSON (default: vuln_configs.json)"
    )

    return parser
        

def main():

    parser = parse_args()
    args = parser.parse_args()

    # If user didn't specify anything – show help and exit
    if not args.scan and not args.scan_all:
        parser.print_help()
        return

    manager = ScansManager()

    if args.scan_all:
        targets = ["ssh", "limits", "resolv", "login_defs", "sysctl", "rsyslog"]
    else:
        scan_name = args.scan
        targets = [scan_name]

    for target in targets:
        manager.run_scan(target)

    manager.update_overall_score() # combines the scores of all of the scans into a single one

    displayer = ResultDisplayer()
    displayer.display_overall_score(manager.overall_score)
    displayer.display_all_scans(manager.scans)
    

    if args.json:

        vulnerabilities = VulnerableConfigs()

        vulnerabilities.collect(manager.scans)

        vulnerabilities.save_vuln_config_json()


    

if __name__ == "__main__":
    main()


