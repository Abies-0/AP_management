import os
import yaml
from logger import ConcurrentLogger

class Config:

    def __init__(self, target, filename):
        self.log_path = "./logs/config"
        os.makedirs(self.log_path, exist_ok=True)
        self.target = target
        self.filename = filename
        self.error_log = ConcurrentLogger(filename="%s/error.log" % (self.log_path))

    def get(self):
        try:
            with open(self.filename, "r") as f:
                data = yaml.load(f, Loader=yaml.CLoader)
                return data[self.target]
        except Exception as e:
            self.error_log.error(e)
