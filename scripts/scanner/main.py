from config_paths import CONFIG_PATHS
from rules import ALL_RULES
from parser import ParsedConfig
from scan_results import ScanResults


def main():
    ssh_path = CONFIG_PATHS["ssh"]

    parser = ParsedConfig(ssh_path)

    config_dict = parser.read_config()

    scanner = ScanResults(config_dict, ALL_RULES["ssh"])

    results = scanner.run_checks()

    for r in results:
        print(r)


if __name__ == "__main__":
    main()
