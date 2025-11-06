# core_scanner/main_scanner.py
# --- replace imports at top of file with these (or add missing ones) ---
import datetime
import json
import httpx
import asyncio
from pathlib import Path
import os
import logging

from .json_logger import JSONLogger

# configure module logger (will write to container stdout)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("core_scanner")

class Scanner:
    def __init__(self, target: str, wordlist_1: str, wordlist_2: str,
                 json_file_name: str, json_file_path: str):     
        # Validate target
        if not target or not str(target).strip():
            raise ValueError("target URL is required")
        self.target = target.strip()
        
        # Validate wordlists (paths as-is, no env var resolution)
        self.wordlist_1 = str(wordlist_1).strip() if wordlist_1 else None
        self.wordlist_2 = str(wordlist_2).strip() if wordlist_2 else None
        
        # Validate filename
        if not json_file_name or not str(json_file_name).strip():
            raise ValueError("json_file_name is required")
        self.json_file_name = str(json_file_name).strip()
        
        # Folder name (used in ~/reconsage_logs/<folder>/)
        self.json_file_path = str(json_file_path).strip() if json_file_path else "default"

    def extract_words_from_wordlist(self, wordlist):
        def _try_open(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                return None
            except Exception as e:
                # If some other error occurs (encoding, permission), log and return None
                logger.warning("Error opening wordlist %s: %s", path, e)
                return None
        if not wordlist:
            logger.info("No wordlist path provided (received falsy value).")
            return []
        candidates = []
        wl = str(wordlist).strip()
        # If absolute path was provided, try that first
        if os.path.isabs(wl):
            candidates.append(wl)
        else:
            # raw relative/filename as provided
            candidates.append(wl)
            # try common Seclists absolute path
            candidates.append(os.path.join("/usr/share/seclists", wl))
            candidates.append(os.path.join("/usr/share/seclists", "Fuzzing", wl))
            # try docker-compose mounted path /wordlists
            candidates.append(os.path.join("/wordlists", wl))
            candidates.append(os.path.join("/wordlists", "Fuzzing", wl))
        # deduplicate while preserving order
        seen = set()
        candidates = [p for p in candidates if p not in seen and not seen.add(p)]
        for candidate in candidates:
            if not candidate:
                continue
            data = _try_open(candidate)
            if data is not None:
                logger.info("Loaded wordlist from: %s (items=%d)", candidate, len(data))
                return data
        # nothing worked — log warning and return empty list (do not raise)
        tried = ", ".join(candidates)
        logger.warning("Wordlist not found for '%s'. Tried: %s", wordlist, tried)
        return []


    async def run_scan(self):
        """Main scanning logic"""
        
        # Load wordlists
        lists = []
        if self.wordlist_1:
            lists.append(self.extract_words_from_wordlist(self.wordlist_1))
        if self.wordlist_2:
            lists.append(self.extract_words_from_wordlist(self.wordlist_2))
        
        # Deduplicate domains
        all_domains = list(set([d for sub in lists for d in sub]))
        
        if not all_domains:
            return {
                "error": "No domains loaded from wordlists",
                "status": 400
            }
        
        # Response categories
        target_successful_codes_records = {}
        target_redirect_codes_records = {}
        target_errors_codes_record = {}
        target_server_errors_codes = {}
        some_unexpected_errors = {}
        
        sem = asyncio.Semaphore(100)
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            async def return_codes(domain: str):
                async with sem:
                    try:
                        subdirectory_target = self.target + domain
                        response = await client.get(subdirectory_target)
                        return (response.status_code, str(response.url), len(response.text))
                    except Exception as e:
                        return (None, subdirectory_target, str(e))
            
            tasks = [return_codes(domain) for domain in all_domains]
            results = await asyncio.gather(*tasks)
        
        # Categorize results
        for codes, url, message in results:
            if codes is None:
                some_unexpected_errors[url] = {
                    "status_code": None,
                    "error": message
                }
            elif 200 <= codes < 300:
                target_successful_codes_records[url] = {
                    "status_code": codes,
                    "content_length": message
                }
            elif 300 <= codes < 400:
                target_redirect_codes_records[url] = {
                    "status_code": codes,
                    "content_length": message
                }
            elif 400 <= codes < 500:
                target_errors_codes_record[url] = {
                    "status_code": codes,
                    "content_length": message
                }
            elif codes >= 500:
                target_server_errors_codes[url] = {
                    "status_code": codes,
                    "content_length": message
                }
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Create loggers (all go to ~/reconsage_logs/<json_file_path>/)
        error_logger = JSONLogger(self.json_file_path, f"client_errors_{timestamp}.json")
        redirect_logger = JSONLogger(self.json_file_path, f"redirects_{timestamp}.json")
        server_error_logger = JSONLogger(self.json_file_path, f"server_errors_{timestamp}.json")
        success_logger = JSONLogger(self.json_file_path, self.json_file_name)
        
        # Write logs
        error_path = error_logger.log_to_file(target_errors_codes_record)
        redirect_path = redirect_logger.log_to_file(target_redirect_codes_records)
        server_error_path = server_error_logger.log_to_file(target_server_errors_codes)
        success_path = success_logger.log_to_file(target_successful_codes_records)
        
        # Include files metadata in response
        files_info = {
            "success_log": success_path,
            "client_errors_log": error_path,
            "redirects_log": redirect_path,
            "server_errors_log": server_error_path
        }
        
        # Run false positives analysis
        false_positives_analysis = self.false_positives()
        
        return {
            "message": "Scan complete! Check JSON logs for details.",
            "summary": {
                "total_scanned": len(all_domains),
                "successful": len(target_successful_codes_records),
                "redirects": len(target_redirect_codes_records),
                "client_errors": len(target_errors_codes_record),
                "server_errors": len(target_server_errors_codes),
                "exceptions": len(some_unexpected_errors)
            },
            "files": files_info,
            "false_positives": false_positives_analysis,
            "status": 200
        }

    def false_positives(self):
        """Analyze false positives based on content length patterns"""
        
        # Reconstruct success log path
        logger = JSONLogger(self.json_file_path, self.json_file_name)
        success_file = Path(logger.filepath)
        
        if not success_file.exists():
            return {
                "error": f"Success log file not found at {success_file}",
                "status": 404
            }
        
        with open(success_file, "r", encoding="utf-8") as f:
            success_logs = json.load(f)
        
        # Group by content length
        length_map = {}
        for url, data in success_logs.items():
            length = data["content_length"]
            length_map.setdefault(length, []).append(url)
        
        false_positives_data = []
        urls_passed_all_tests = []
        
        for length, urls in length_map.items():
            if len(urls) > 5:
                for url in urls:
                    false_positives_data.append({
                        "url": url,
                        "reason": "identical_content_length",
                        "content_length": length,
                        "pattern_count": len(urls),
                        "confidence": "medium"
                    })
            
            elif length < 100:
                for url in urls:
                    false_positives_data.append({
                        "url": url,
                        "reason": "suspiciously_small_response",
                        "content_length": length,
                        "confidence": "low"
                    })
            
            elif length > 50000:
                for url in urls:
                    false_positives_data.append({
                        "url": url,
                        "reason": "suspiciously_large_response",
                        "content_length": length,
                        "confidence": "low"
                    })
            else:
                for url in urls:
                    urls_passed_all_tests.append({
                        "url": url,
                        "content_length": length,
                        "confidence": "high",
                        "note": "Passed basic false positive checks"
                    })
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        fp_log_name = f"false_positives_{timestamp}.json"
        verified_log_name = f"verified_finds_{timestamp}.json"
        
        fp_logger = JSONLogger(self.json_file_path, fp_log_name)
        verified_logger = JSONLogger(self.json_file_path, verified_log_name)
        
        fp_path = fp_logger.log_to_file(false_positives_data)
        verified_path = verified_logger.log_to_file(urls_passed_all_tests)
        
        total = len(success_logs)
        fp_count = len(false_positives_data)
        verified_count = len(urls_passed_all_tests)
        fp_ratio = fp_count / total if total > 0 else 0
        
        warning = None
        if fp_ratio > 0.7:
            warning = "⚠️ Very high false positive rate!"
        elif fp_ratio > 0.5:
            warning = "⚠️ High false positive rate detected."
        
        return {
            "message": "False positive analysis complete!",
            "files": {
                "false_positives": fp_path,
                "verified_finds": verified_path
            },
            "summary": {
                "total_successful": total,
                "likely_false_positives": fp_count,
                "verified_finds": verified_count,
                "unique_content_lengths": len(length_map),
                "false_positive_ratio": round(fp_ratio, 2)
            },
            "warning": warning,
            "status": 200
        }