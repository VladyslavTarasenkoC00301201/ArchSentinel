import os    # path and file checks. directories
import glob  #matching pattens



class ParsedConfig:
    def __init__(self, file_path):
        # file path can be a string(file), string(directory), list of paths

        if isinstance(file_path, str):
            self.paths = [file_path]
        else:
            self.paths = file_path
        self.config = {}


    def read_config(self):
        for path in self.paths:
            if os.path.isfile(path):
                self.parse_file(path)

            elif os.path.isdir(path):
                conf_files = sorted(glob.glob(os.path.join(path, "*.conf")))
                for file in conf_files:
                    self.parse_file(file)
            else:
                continue


        return self.config 


    def parse_file(self, path):
        try:

            with open(path, "r") as config_file:
                for line in config_file:
                    line = line.strip()
                    if line.startswith("#") or line =="":
                        continue


                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0]
                        value = " ".join(parts[1:])
                        self.config[key] = value
        except Exception as e:
            print(f"Error reading {path}: {e}")


