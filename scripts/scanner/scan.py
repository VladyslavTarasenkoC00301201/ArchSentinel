
def read_sshd_config(path="/etc/ssh/sshd_config"):
    config = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or line == "":
                continue
            parts = line.split()
            if len(parts) >= 2:
                key = parts[0]
                value = " ".join(parts[1:])
                config[key] = value
    return config


def check_settings(config):
    results = []

    # Example checks
    checks = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
    }

    for key, expected in checks.items():
        current = config.get(key, None)

        if current is None:
            print(current)
            status = "MISSING"
        elif current.lower() == expected.lower():
            status = "OK"
        else:
            status = "BAD"

        results.append((key, current, expected, status))

    return results


def main():
    config = read_sshd_config()
    results = check_settings(config)

    print("\n--- SSH Configuration Scan ---\n")
    for key, current, expected, status in results:
        print(f"{key}: current={current}, expected={expected} --> {status}")


if __name__ == "__main__":
    main()

