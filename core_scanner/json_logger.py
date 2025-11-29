# core_scanner/json_logger.py
from pathlib import Path
import json
import re
import datetime

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
    Logs JSON files inside:
        ~/reconsage_logs/<folder_name>/
    
    Behavior:
    - If file exists → auto-create a new one with timestamp.
    """

    def __init__(self, json_file_path: str, json_file_name: str):
        if not json_file_name:
            raise ValueError("json_file_name cannot be empty")

        # sanitize filename
        base_name = sanitize(json_file_name)
        if not base_name.lower().endswith(".json"):
            base_name += ".json"

        self.base_name = base_name

        # sanitize folder name
        folder_name = sanitize(json_file_path) if json_file_path else "default"

        # final directory inside home
        self.dir_path = Path.home() / "reconsage_logs" / folder_name
        self.dir_path.mkdir(parents=True, exist_ok=True)

        # initial file path (may be renamed later)
        self.filepath = self._get_unique_filepath()

    def _get_unique_filepath(self):
        """
        If file exists, create a timestamped version instead of overwriting.
        """
        fp = self.dir_path / self.base_name

        if not fp.exists():
            # no conflict
            return fp

        # conflict → generate timestamped file
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        stem = self.base_name[:-5]  # remove .json
        new_name = f"{stem}_{timestamp}.json"
        return self.dir_path / new_name

    def log_to_file(self, logs, indent=2):
        """
        Write logs into a guaranteed-unique JSON file.
        Returns absolute file path.
        """
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=indent, ensure_ascii=False)

        return str(self.filepath.resolve())
