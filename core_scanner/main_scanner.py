import datetime
import json
import os
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
            "status": 200
        }
    def false_positives(self):
        full_path = os.path.join(self.json_file_path, self.json_file_name)
        try:
            with open(full_path, "r", encoding='utf-8') as f:
                success_logs = json.load(f)
        except FileNotFoundError as e:
          print("file not found exception")
        lenght_map = {}
        for url, data in success_logs.items():
            length = data["content_length"]
            if length not in lenght_map:
                lenght_map[length] = []
            
            lenght_map[length].append(url)
        urls_passed_all_test = []
        false_positives_data = []
        for length, urls in lenght_map.items() :
            if len(url) > 5:
                for url in urls:
                    false_positives_data.append({
                        "url" : url,
                        "reason" : "content_length_same",
                        "length" : length,
                        "pattern_counts" : len(urls),
                        "fake_positive_probability": "medium"
                    })
            elif length < 100 :
                for url in urls:
                    false_positives_data.append({
                        "url" : url,
                        "reason" : "response_is_too_small",
                        "length" : length,
                        "fake_positive_probability": "low"
                    })
            elif length > 1500:
                for url in urls:
                    false_positives_data.append({
                        "url" : url,
                        "reason" : "response is too big",
                        "length" : length,
                        "fake_positive_possibility" : "low"
                    })
            
            else :
                for url in urls:
                    urls_passed_all_test.append({
                        "url" : url,
                        "length" : length,
                        "fake_positive_chances" : "still consider for the another advance tests if this is still not much for you"
                    })
            timestamps = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            fp_log_file_name = f"fp_logger{timestamps}.json"
            fp_logger = JSONLogger(self.json_file_path, name=fp_log_file_name)
            passed_urls_file_name = f"passed_urls_{timestamps}.json"
            passed_url_logger = JSONLogger(self.json_file_path, passed_urls_file_name)
            fp_logger.log_to_file(false_positives_data)
            passed_url_logger.log_to_file(urls_passed_all_test)
            return {
                "passed_urls_json_file_name" : passed_urls_file_name,
                "fp_file_name" : fp_log_file_name,
                "message" : "please use the names of the fp_log_file_names in the advance scanner too for it will be very useful applys for the passed urls too maybe they can be still suspicious",
                "summary" : {
                    "len_fp_logs" : len(false_positives_data), 
                    "passed_urls" : len(urls_passed_all_test),
                    "lengths_map" : len(lenght_map)
                }
            }