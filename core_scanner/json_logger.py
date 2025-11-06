# json_logger.py
from pathlib import Path
import json
import re
import os
from typing import Any, Optional


class JSONLogger:
    """
    JSONLogger writes JSON logs into a folder that always lives under the current user's home directory.

    Behavior:
    - The `path` parameter can be:
        * An absolute Windows path like "C:\\Users\\me\\my_logs"
        * An absolute Linux path like "/var/logs/my_logs"
        * A relative path or just a folder name like "my_logs" or "foo/bar"
      In all cases the logger will take the final path component (e.g. "my_logs" or "bar")
      and create that directory under the user's home directory.
      Example: if home is /home/glitch and user passes "C:\\Users\\me\\my_logs" -> logs go to
      /home/glitch/my_logs

    - The `name` parameter is the filename (must be provided). If it lacks ".json", it will be appended.
    - The final write location will always be a subdirectory of the user's home directory.
    - Path components are sanitized to remove suspicious characters and prevent directory traversal.
    """

    # allowed pattern for folder/file names: letters, numbers, dash, underscore, dot
    _SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

    def __init__(self, path: Optional[str], name: str):
        """
        :param path: user-provided path or folder name (may be absolute or relative). If None or empty,
                     a default folder name 'reconsage_logs' under home will be used.
        :param name: filename for the JSON output (e.g. 'scan_results.json' or 'scan_results')
        :raises ValueError: if name is empty or invalid after sanitization
        """
        if not name or not str(name).strip():
            raise ValueError("You must provide a valid json filename in 'name'.")

        home = Path.home()

        # Determine folder name: use last path component of whatever user passed
        folder_name = "reconsage_logs"
        if path and str(path).strip():
            # Normalize slashes/backslashes; Path will handle OS-specific separators
            user_path = Path(str(path))
            last = user_path.name  # last component (works for absolute or relative)
            # If user passed a path that ends with a separator, .name could be empty; try parent
            if not last:
                last = user_path.parent.name or folder_name
            # sanitize the folder name (remove unsafe chars)
            folder_name = self._sanitize_name(last) or folder_name
        else:
            # no path provided -> use default
            folder_name = "reconsage_logs"

        # Ensure folder_name is not suspicious (no ".." etc). If it is, fallback to default.
        if folder_name in ("", ".", ".."):
            folder_name = "reconsage_logs"

        # Build final path under home (always)
        final_dir = home / folder_name

        # Resolve but don't allow escaping home
        try:
            final_dir = final_dir.resolve(strict=False)
        except Exception:
            # fallback to safe join
            final_dir = Path(str(home)) / folder_name

        # defensive check: ensure final_dir is inside the home directory
        try:
            # On some systems resolve may behave oddly for non-existing paths; compare parts instead
            if home.resolve() not in final_dir.resolve().parents and final_dir.resolve() != home.resolve():
                # If not inside home, force it to be inside home
                final_dir = home / folder_name
        except Exception:
            final_dir = home / folder_name

        # create directory
        os.makedirs(final_dir, exist_ok=True)

        # Sanitize file name and ensure .json suffix
        safe_name = self._sanitize_name(Path(name).name)
        if not safe_name:
            raise ValueError("Invalid json filename after sanitization.")
        if not safe_name.lower().endswith(".json"):
            safe_name = safe_name + ".json"

        self.path = str(final_dir)
        self.name = safe_name
        self.filepath = os.path.join(self.path, self.name)

    @staticmethod
    def _sanitize_name(name: str) -> str:
        """Return a safe filename/folder name by stripping unsafe chars and trimming length."""
        if not name:
            return ""
        # replace unsafe chars with underscore
        cleaned = JSONLogger._SAFE_NAME_RE.sub("_", name)
        # collapse multiple underscores
        cleaned = re.sub(r"_+", "_", cleaned)
        # trim to sensible length
        return cleaned.strip("_")[:255]

    def log_to_file(self, logs: Any, mode: str = "w", ensure_ascii: bool = False, indent: int = 2) -> str:
        """
        Write `logs` (any JSON-serializable object) to the configured json file.

        :param logs: JSON-serializable content to write
        :param mode: file mode, default "w". You may pass "a" to append (appends valid JSON not guaranteed).
        :param ensure_ascii: passed to json.dump
        :param indent: indentation level for pretty printing
        :return: the absolute path to the written file
        """
        # Defensive: ensure path exists before writing
        os.makedirs(self.path, exist_ok=True)

        with open(self.filepath, mode, encoding="utf-8") as f:
            json.dump(logs, f, indent=indent, ensure_ascii=ensure_ascii)
        return self.filepath

    def __repr__(self) -> str:
        return f"JSONLogger(path={self.path!r}, name={self.name!r})"
