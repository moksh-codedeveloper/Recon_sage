import json, os

class JSONLogger:
    def __init__(self, path:str, name:str):
        self.path = path
        self.name = name
        os.makedirs(path, exist_ok=True)
        if not name :
            raise ValueError("Passs the appropriate name here ")
    def log_to_file(self, logs):
        print('='*60)
        print("Your json logging has been initiated and will be over soon enough")
        file = os.path.join(self.path, self.name)
        with open(file, "w", encoding='utf-8') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
        print('='*60)