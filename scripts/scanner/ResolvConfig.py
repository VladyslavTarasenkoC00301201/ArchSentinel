from .parsed_config import ParsedConfig




class ResolvConfig(ParsedConfig):
    def __init__(self, file_path):
        super().__init__(file_path)
        # override parsed structure with resolv-style lists
        self.config = {
            "nameserver": [],
            "options": [],
            "search": [],
        }

    def _parse_file(self, path):
        # we override ONLY the file parsing, not directory/file logic
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()

                    # nameserver 1.1.1.1
                    if parts[0] == "nameserver" and len(parts) >= 2:
                        self.config["nameserver"].append(parts[1])

                    # options edns0 trust-ad
                    elif parts[0] == "options" and len(parts) >= 2:
                        self.config["options"].extend(parts[1:])

                    # search example.com
                    elif parts[0] == "search" and len(parts) >= 2:
                        self.config["search"].extend(parts[1:])
        except Exception as e:
            print(f"Error parsing resolv.conf: {e}")
        

