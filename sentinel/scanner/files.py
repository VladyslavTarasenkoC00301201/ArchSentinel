def parse_kv_config(path: str):
    result = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                result[parts[0]] = " ".join(parts[1:])
    return result

