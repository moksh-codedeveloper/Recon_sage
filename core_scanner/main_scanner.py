import datetime
import json
import os
from pathlib import Path
import httpx
import asyncio
from .json_logger import JSONLogger

class Scanner:
    def __init__(self, target:str, wordlist_1:str, wordlist_2:str, json_file_name:str, json_file_path:str):
        self.target = target
        self.wordlist_1 = wordlist_1
        self.wordlist_2 = wordlist_2
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
        
    def extract_words_from_wordlist(self, wordlist):
        data = []
        with open(wordlist, "r", encoding='utf-8') as f:
            for words in f:
                s = words.strip()
                if s:
                    data.append(s)
        return data
    
    async def run_scan(self):
        # Load wordlists
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
        
        # Rate limiting
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
            
            # Execute all tasks
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
        
        # Generate log filenames with timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Save separate logs
        error_logger = JSONLogger(
            path=self.json_file_path,
            name=f"client_errors_{timestamp}.json"
        )
        redirect_logger = JSONLogger(
            path=self.json_file_path,
            name=f"redirects_{timestamp}.json"
        )
        server_error_logger = JSONLogger(
            path=self.json_file_path,
            name=f"server_errors_{timestamp}.json"
        )
        success_logger = JSONLogger(
            path=self.json_file_path,
            name=self.json_file_name
        )
        
        # Write logs
        error_logger.log_to_file(target_errors_codes_record)
        redirect_logger.log_to_file(target_redirect_codes_records)
        server_error_logger.log_to_file(target_server_errors_codes)
        success_logger.log_to_file(target_successful_codes_records)
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
            "unexpected_errors": some_unexpected_errors,
            "status": 200,
        }
    def false_positives(self):
        
            # Reconstruct actual JSON path using JSONLogger's logic
        logger = JSONLogger(self.json_file_path, self.json_file_name)
        full_path = Path(logger.filepath)  # THIS is the real file location

        if not full_path.exists():
            return {
                "error": f"Success log file not found at {full_path}",
                "status": 404
            }

        with open(full_path, "r", encoding='utf-8') as f:
            success_logs = json.load(f)
        # Group by content length
        length_map = {}
        for url, data in success_logs.items():
            length = data["content_length"]
            if length not in length_map:
                length_map[length] = []
            length_map[length].append(url)
        
        # Analyze patterns
        false_positives_data = []
        urls_passed_all_tests = []
        
        for length, urls in length_map.items():
            # Pattern 1: Many URLs with identical length
            if len(urls) > 5:  # ← FIXED: Check count of URLs
                for url in urls:
                    false_positives_data.append({
                        "url": url,
                        "reason": "identical_content_length",
                        "content_length": length,
                        "pattern_count": len(urls),
                        "confidence": "medium"
                    })
            
            # Pattern 2: Suspiciously small response
            elif length < 100:
                for url in urls:
                    false_positives_data.append({
                        "url": url,
                        "reason": "suspiciously_small_response",
                        "content_length": length,
                        "confidence": "low"
                    })
            
            # Pattern 3: Suspiciously large response
            elif length > 50000:  # 50KB threshold (was 1500, too low!)
                for url in urls:
                    false_positives_data.append({
                        "url": url,
                        "reason": "suspiciously_large_response",
                        "content_length": length,
                        "confidence": "low"
                    })
            
            # Passed all tests
            else:
                for url in urls:
                    urls_passed_all_tests.append({
                        "url": url,
                        "content_length": length,
                        "confidence": "high",
                        "note": "Passed basic false positive checks"
                    })
        
        # NOW create loggers ONCE (outside loop!)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        fp_log_file_name = f"false_positives_{timestamp}.json"
        passed_urls_file_name = f"verified_finds_{timestamp}.json"
        
        fp_logger = JSONLogger(self.json_file_path, fp_log_file_name)
        passed_logger = JSONLogger(self.json_file_path, passed_urls_file_name)
        
        # Write logs ONCE
        fp_logger.log_to_file(false_positives_data)
        passed_logger.log_to_file(urls_passed_all_tests)
        
        # Calculate ratio
        total = len(success_logs)
        fp_count = len(false_positives_data)
        verified_count = len(urls_passed_all_tests)
        fp_ratio = fp_count / total if total > 0 else 0
        
        # Warning based on ratio
        warning = None
        if fp_ratio > 0.7:
            warning = "⚠️ Very high false positive rate! Review results carefully."
        elif fp_ratio > 0.5:
            warning = "⚠️ High false positive rate detected."
        
        return {
            "message": "False positive analysis complete!",
            "files": {
                "false_positives": fp_log_file_name,
                "verified_finds": passed_urls_file_name
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