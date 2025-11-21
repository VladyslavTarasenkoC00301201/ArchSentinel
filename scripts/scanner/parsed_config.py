class ParsedConfig:
    def __init__(self, file_path):
        self.config_file = file_path
        self.config = {}

    def read_config(self):
        with open(self.config_file, "r") as config_file:
            for line in config_file:
                line = line.strip()
                if line.startswith("#") or line =="":
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0]
                    value = " ".join(parts[1:])
                    self.config[key] = value
        return self.config
