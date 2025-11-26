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
                 json_file_name: str, json_file_path: str, timeout, concurrency):     
        # Validate target
        if not target or not str(target).strip():
            raise ValueError("target URL is required")
        self.target = target.strip()
        self.timeout = timeout
        # Validate wordlists (paths as-is, no env var resolution)
        self.wordlist_1 = str(wordlist_1).strip() if wordlist_1 else None
        self.wordlist_2 = str(wordlist_2).strip() if wordlist_2 else None
        self.concurrency_rate = concurrency
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
        pf = PassiveFingerprint(target=self.target, timeout=self.timeout, concurrency=self.concurrency_rate)
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
            url = scanned_result["url"]
            content_length = scanned_result["content_length"]
            result[url] = {
                "status_code" : status_code,
                "headers" : headers,
                "hash_text" : hash_text,
                "latency_ms" : latency_ms,
                "timestamps" : timestamp,
                "content_length" : content_length 
            }
            if status_code >= 200 and status_code < 300:
                success_status_code.append(url)
            elif status_code >= 300 and status_code < 400:
                redirect_status_code.append(url)
            elif status_code >= 400 and status_code < 500:
                error_status_code.append(url)
            else : 
                server_status_code.append(url)
        
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