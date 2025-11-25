import json
from .config_paths import CONFIG_PATHS




class Enforcer:
    def __init__(self, issues_file="vuln_configs.json"):
        with open(issues_file, "r") as f:
            self.issues = json.load(f)

    def enforce(self):
        for issue in self.issues:
            scan = issue["scan_name"]
            key = issue["key"]
            expected = issue["expected"]

            file_path = CONFIG_PATHS.get(scan)
            if not file_path:
                print(f"No config path for {scan}")
                continue

            print(f"Fixing {scan}: {key} → {expected}")
            self._fix_in_file(file_path, key, expected)

    def _fix_in_file(self, file_path, key, expected_value):
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return

        key_found = False
        new_lines = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#") or stripped == "":
                new_lines.append(line)
                continue

            parts = stripped.split()
            if parts[0] == key:
                new_line = f"{key} {expected_value}\n"
                new_lines.append(new_line)
                key_found = True
            else:
                new_lines.append(line)

        # If key was missing → append it
        if not key_found:
            new_lines.append(f"{key} {expected_value}\n")

        # Write the modified file
        with open(file_path, "w") as f:
            f.writelines(new_lines)

        print(f"Updated {file_path}")

