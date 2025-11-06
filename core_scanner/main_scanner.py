# core_scanner/main_scanner.py
import datetime
import json
import os
import httpx
import asyncio
from pathlib import Path

from .json_logger import JSONLogger


class Scanner:
    def __init__(self, target: str, wordlist_1: str, wordlist_2: str,
                 json_file_name: str, json_file_path: str):

        self.target = target
        self.wordlist_1 = wordlist_1
        self.wordlist_2 = wordlist_2

        # raw inputs
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path

        # after scan completes we store resolved filepaths here
        self.saved_success_log = None


    def extract_words_from_wordlist(self, wordlist):
        data = []
        with open(wordlist, "r", encoding="utf-8") as f:
            for words in f:
                s = words.strip()
                if s:
                    data.append(s)
        return data


    async def run_scan(self):

        # load wordlists
        lists = []
        if self.wordlist_1:
            lists.append(self.extract_words_from_wordlist(self.wordlist_1))
        if self.wordlist_2:
            lists.append(self.extract_words_from_wordlist(self.wordlist_2))

        all_domains = [d for sub in lists for d in sub]

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

        # categorize results
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

        # JSONLogger writes paths with fallback rules
        error_logger = JSONLogger(self.json_file_path, f"client_errors_{timestamp}.json")
        redirect_logger = JSONLogger(self.json_file_path, f"redirects_{timestamp}.json")
        server_error_logger = JSONLogger(self.json_file_path, f"server_errors_{timestamp}.json")
        success_logger = JSONLogger(self.json_file_path, self.json_file_name)

        # write logs & COLLECT REAL PATHS
        error_path = error_logger.log_to_file(target_errors_codes_record)
        redirect_path = redirect_logger.log_to_file(target_redirect_codes_records)
        server_error_path = server_error_logger.log_to_file(target_server_errors_codes)
        success_path = success_logger.log_to_file(target_successful_codes_records)

        # save success path for false positives later
        self.saved_success_log = success_path
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
            "files": {
                "success_log": success_path,
                "client_errors_log": error_path,
                "redirects_log": redirect_path,
                "server_errors_log": server_error_path
            },
            "false_positives": false_positives_analysis,
            "status": 200
        }


    def false_positives(self):

        # reconstruct the REAL success log path ALWAYS using JSONLogger
        logger = JSONLogger(self.json_file_path, self.json_file_name)
        success_file = Path(logger.filepath)

        if not success_file.exists():
            return {
                "error": f"Success log file not found at {success_file}",
                "status": 404
            }

        with open(success_file, "r", encoding="utf-8") as f:
            success_logs = json.load(f)

        # group by content length
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
