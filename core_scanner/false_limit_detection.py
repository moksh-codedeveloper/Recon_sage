import json
import os
# from target_fingerprinting import PassiveFingerprint

class FalsePositive:
    def __init__(self, timeout, target, json_full_name, json_full_path): 
        os.makedirs(json_full_path, exist_ok=True)
        self.target = target 
        self.json_name = json_full_name
        self.json_path = json_full_path
        self.full_path = os.path.join(self.json_path, self.json_name)
        self.timeout = timeout

    def read_json(self):
        try:
            with open(self.full_path, "r", encoding="utf-8") as f:
                result = json.load(f)
                return result
        except FileNotFoundError:
            raise FileNotFoundError("The file or path doesn't exist buddy")

    def detection(self):
        pass