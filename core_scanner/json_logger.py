# core_scanner/json_logger.py
from pathlib import Path
import json
import re

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

def sanitize(name: str) -> str:
    """Sanitize filename to prevent path traversal attacks"""
    if not name:
        return ""
    name = _SAFE_NAME.sub("_", name)
    name = re.sub(r"_+", "_", name)
    return name.strip("_")[:255]


class JSONLogger:
    """
    Logs JSON files to user's home directory ONLY.
    Path: ~/reconsage_logs/<folder_name>/<filename>
    """
    
    def __init__(self, json_file_path: str, json_file_name: str):
        if not json_file_name:
            raise ValueError("json_file_name cannot be empty")
        
        # Sanitize filename
        safe_name = sanitize(json_file_name)
        if not safe_name.lower().endswith(".json"):
            safe_name += ".json"
        
        # Sanitize folder name (from json_file_path parameter)
        folder_name = sanitize(json_file_path) if json_file_path else "default"
        
        # ALWAYS use home directory - no fallbacks, no env vars
        home = Path.home()
        final_dir = home / "reconsage_logs" / folder_name
        
        # Create directory if it doesn't exist
        final_dir.mkdir(parents=True, exist_ok=True)
        
        self.path = final_dir
        self.name = safe_name
        self.filepath = final_dir / safe_name
    
    def log_to_file(self, logs, indent=2):
        """Write logs to JSON file and return absolute path"""
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=indent, ensure_ascii=False)
        return str(self.filepath.resolve())