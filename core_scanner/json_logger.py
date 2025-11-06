# json_logger.py
from pathlib import Path
import json
import re
import os
import tempfile
from typing import Any, Optional

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

def _sanitize_name(name: str) -> str:
    if not name:
        return ""
    cleaned = _SAFE_NAME_RE.sub("_", name)
    cleaned = re.sub(r"_+", "_", cleaned)
    return cleaned.strip("_")[:255]

class JSONLogger:
    """
    Writes logs into: HOME/<folder>/<file>.json
    Falls back to:
        ./<folder>/
        or system tmp/ directory
    """

    def __init__(self, path: Optional[str], name: str, fallback_to_cwd: bool = True):
        if not name or not str(name).strip():
            raise ValueError("A valid json filename must be provided.")

        # Determine folder name
        if path and str(path).strip():
            folder_candidate = Path(path).name or "reconsage_logs"
        else:
            folder_candidate = "reconsage_logs"

        folder_name = _sanitize_name(folder_candidate) or "reconsage_logs"

        home = Path.home()
        candidate_dir = (home / folder_name).resolve()

        # sanitize filename
        safe_name = _sanitize_name(Path(name).name)
        if not safe_name:
            raise ValueError("Invalid json filename after sanitization.")

        if not safe_name.lower().endswith(".json"):
            safe_name += ".json"

        # try writing under HOME
        final_dir = None
        try:
            os.makedirs(candidate_dir, exist_ok=True)
            test_file = candidate_dir / ".write_test.tmp"
            with open(test_file, "w", encoding="utf-8") as tf:
                tf.write("ok")
            test_file.unlink(missing_ok=True)
            final_dir = candidate_dir
        except Exception:
            # fallback #1: cwd/<folder_name>
            if fallback_to_cwd:
                fallback_dir = (Path.cwd() / folder_name).resolve()
                try:
                    os.makedirs(fallback_dir, exist_ok=True)
                    test_file = fallback_dir / ".write_test.tmp"
                    with open(test_file, "w", encoding="utf-8") as tf:
                        tf.write("ok")
                    test_file.unlink(missing_ok=True)
                    final_dir = fallback_dir
                except Exception:
                    # fallback #2: tmp/<folder_name>
                    tmp = Path(tempfile.gettempdir()) / folder_name
                    os.makedirs(tmp, exist_ok=True)
                    final_dir = tmp
            else:
                raise PermissionError(f"Cannot write to {candidate_dir}.")

        self.path = str(final_dir)
        self.name = safe_name
        self.filepath = str(Path(final_dir) / safe_name)

    def log_to_file(self, logs: Any, mode="w", ensure_ascii=False, indent=2) -> str:
        os.makedirs(self.path, exist_ok=True)
        try:
            with open(self.filepath, mode, encoding="utf-8") as f:
                json.dump(logs, f, indent=indent, ensure_ascii=ensure_ascii)
            return self.filepath
        except PermissionError as e:
            raise PermissionError(
                f"Permission denied writing to {self.filepath}. "
                f"Check directory permissions or choose another json_file_path. ({e})"
            )
