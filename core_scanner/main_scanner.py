# core_scanner/main_scanner.py
# --- replace imports at top of file with these (or add missing ones) ---
import datetime
import json
import httpx
import asyncio
from pathlib import Path
import logging

from core_scanner.target_fingerprinting import PassiveFingerprint

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
        self.timeout = 10
        # Validate wordlists (paths as-is, no env var resolution)
        self.wordlist_1 = str(wordlist_1).strip() if wordlist_1 else None
        self.wordlist_2 = str(wordlist_2).strip() if wordlist_2 else None
        self.concurrency_rate = 100
        # Validate filename
        if not json_file_name or not str(json_file_name).strip():
            raise ValueError("json_file_name is required")
        self.json_file_name = str(json_file_name).strip()
        
        # Folder name (used in ~/reconsage_logs/<folder>/)
        self.json_file_path = str(json_file_path).strip() if json_file_path else "default"

    async def run_scan(self):
        result = {}
        error_status_code = []
        redirect_status_code = []
        success_status_code = []
        server_status_code = []
        pf = PassiveFingerprint(target=self.target, timeout=self.timeout)
        # Ensure extractor returns a list (fallback to empty list if None)
        wordlist_data_1 = pf.wordlist_data_extractor(wordlist=self.wordlist_1) or []
        wordlist_data_2 = pf.wordlist_data_extractor(wordlist=self.wordlist_2) or []
        # Combine safely (list.append returns None), filter out any None sublists
        wordlist_data = []
        if isinstance(wordlist_data_1, list):
            wordlist_data.extend([sub for sub in wordlist_data_1 if sub])
        if isinstance(wordlist_data_2, list):
            wordlist_data.extend([sub for sub in wordlist_data_2 if sub])
        # Flatten into a single list of domains, guarding against None sublists
        all_domain = [d for sub in wordlist_data for d in (sub or [])]
        for domain in all_domain:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            scanned_result = await pf.scan_data(domain=domain)
            status_code = scanned_result["status_code"]
            headers = scanned_result["headers"]
            hash_text = scanned_result["hashed_body"]
            latency_ms = scanned_result["latency_ms"]
            response_object = scanned_result["response_object"]
            content_length = scanned_result["content_length"]
            result[response_object.url] = {
                "status_code" : status_code,
                "headers" : headers,
                "hash_text" : hash_text,
                "latency_ms" : latency_ms,
                "timestamps" : timestamp,
                "content_length" : content_length 
            }
            if status_code >= 200 and status_code < 300:
                success_status_code.append(response_object.url)
            elif status_code >= 300 and status_code < 400:
                redirect_status_code.append(response_object.url)
            elif status_code >= 400 and status_code < 500:
                error_status_code.append(response_object.url)
            else : 
                server_status_code.append(response_object.url)
        
        success_logs = {
            "message" : "The detailed logs to understand your victim more clearly",
            "result" : result,
            "successfully_accessed_urls" : success_status_code,
            "error_accessing_url" : len(error_status_code),
            "redirect_access_url" : len(redirect_status_code),
            "server_error_access_url" : len(server_status_code),
        }
        success_logger = JSONLogger(json_file_name=self.json_file_name, json_file_path=self.json_file_path)
        success_logger.log_to_file(success_logs)
        return {
            "message" : "Successfully done the scan results are all created!",
            "scanned_result" : result,
            "more_detailed" : {
                "length_of_successful_url" : len(success_status_code),
                "length_of_error_url" : len(error_status_code),
                "length_of_redirect_url" : len(redirect_status_code),
                "length_of_server_error" : len(server_status_code)
            },
            "status_code" : 200
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