# core_scanner/json_logger.py
from pathlib import Path
import json
import os
import re
import tempfile


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

def sanitize(name: str) -> str:
    if not name:
        return ""
    name = _SAFE_NAME.sub("_", name)
    name = re.sub(r"_+", "_", name)
    return name.strip("_")[:255]


class JSONLogger:
    """
    Logging resolution priority:
    
    1. LOG_DIR environment variable (absolute path)
    2. Absolute json_file_path (if RECONSAGE_ALLOW_ABSOLUTE=1)
    3. HOME/<json_file_path>
    4. CWD/<json_file_path>
    5. TMP/<json_file_path>
    """

    def __init__(self, json_file_path: str, json_file_name: str):
        if not json_file_name:
            raise ValueError("json_file_name cannot be empty")

        # sanitize filename
        safe_name = sanitize(json_file_name)
        if not safe_name.lower().endswith(".json"):
            safe_name += ".json"

        # 1) Highest priority: LOG_DIR environment variable
        env_dir = os.getenv("LOG_DIR")
        if env_dir:
            candidate = Path(env_dir).expanduser()
            if candidate.exists() and os.access(candidate, os.W_OK):
                final_dir = candidate
            else:
                try:
                    candidate.mkdir(parents=True, exist_ok=True)
                    final_dir = candidate
                except Exception:
                    final_dir = None
        else:
            final_dir = None

        # 2) Absolute json_file_path (only if allowed)
        if final_dir is None and json_file_path:
            p = Path(json_file_path)
            allow_abs = os.getenv("RECONSAGE_ALLOW_ABSOLUTE", "0") == "1"
            if p.is_absolute() and allow_abs:
                try:
                    p.mkdir(parents=True, exist_ok=True)
                    final_dir = p
                except Exception:
                    final_dir = None

        # 3) HOME/<folder>
        if final_dir is None:
            home = Path.home()
            folder = sanitize(json_file_path) if json_file_path else "reconsage_logs"
            candidate = home / folder
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                final_dir = candidate
            except Exception:
                final_dir = None

        # 4) CWD/<folder>
        if final_dir is None:
            cwd = Path.cwd()
            folder = sanitize(json_file_path) if json_file_path else "reconsage_logs"
            candidate = cwd / folder
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                final_dir = candidate
            except Exception:
                final_dir = None

        # 5) TMP/<folder>
        if final_dir is None:
            tmp = Path(tempfile.gettempdir())
            folder = sanitize(json_file_path) if json_file_path else "reconsage_logs"
            final_dir = tmp / folder
            final_dir.mkdir(parents=True, exist_ok=True)

        self.path = final_dir
        self.name = safe_name
        self.filepath = final_dir / safe_name


    def log_to_file(self, logs, indent=2):
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=indent, ensure_ascii=False)
        return str(self.filepath)
