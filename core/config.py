# core/config.py

import yaml
import os

class ConfigManager:
    def __init__(self, config_path="config/settings.yaml"):
        self.config_path = config_path
        self.config = {}

    def load_config(self):
        if not os.path.isfile(self.config_path):
            print(f"[!] Config file not found at {self.config_path}. Using defaults.")
            return {}
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            print(f"[!] Error reading config file: {e}")
            self.config = {}

        return self.config