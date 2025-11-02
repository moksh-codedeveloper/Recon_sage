import asyncio
import datetime
import httpx
from .json_logger import JSONLogger
class ScanDataArrangement:
    def __init__(self, target, wordlist_path_1, wordlist_path_2, json_file_path, json_file_name):
        self.target_name = target
        self.wordlist_1 = wordlist_path_1
        self.wordlist_2 = wordlist_path_2
        self.logger = JSONLogger(json_file_path, json_file_name)
        
        if not target.startswith(("https://", "http://")):
            raise ValueError("Target URL must start with the http:// or https://")
        if not target.endswith("/"):
            self.target_name = target + "/"

    def now_iso(self):
        return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    def extract_data_wordlist(self, wordlist_path):
        if not wordlist_path:
            raise ValueError("The path is empty bro you alright because you don't seem that you are programmer are you ??")
        extracted_data_values = []
        with open(wordlist_path, "r", encoding="utf-8") as f:
            for lines in f:
                s = lines.strip()
                if s:
                    extracted_data_values.append(s)
            
        return extracted_data_values

    async def scanner(self):
         # load wordlists that are provided
        present_dirs = []
        not_present_dirs = []
        errors = []
        lists = []
        if self.wordlist_1:
            lists.append(self.extract_data_wordlist(self.wordlist_1))
        if self.wordlist_2:
            lists.append(self.extract_data_wordlist(self.wordlist_2))

        # flatten
        all_domains = [d for sub in lists for d in sub]
        sem = asyncio.Semaphore(100)
        async with httpx.AsyncClient(timeout=10) as client:
            async def check_urls(domain):
                subdomain_target = self.target_name + domain
                async with sem:
                    try:
                        response = await client.get(subdomain_target)
                        return (response.status_code, str(response.url), None)
                    except Exception as exc:
                        return (None, subdomain_target, str(exc))
        
            tasks = [check_urls(domain) for domain in all_domains]
            result = await asyncio.gather(*tasks)
        for status, url, error in result :
            if error :
                errors.append({"error" : error, "urls" : url})
            else:
                if status == 200:
                    present_dirs.append(url)
                else: 
                    not_present_dirs.append(url)
        
        logs_for_file = {
            "message" : "here is the comprehensive list of targets which are present and which are not ",
            "present targets" : present_dirs,
            "errors_that_came" : errors,
            "not present targets" : not_present_dirs,
            "timestamps" : self.now_iso()
        }
        self.logger.log_to_file(logs_for_file)
        return {
            "message" : "the result is as you can see here in the given lists" ,
            "present_counts" : len(present_dirs),
            "not_present_counts" : len(not_present_dirs),
            "count_of_errors_that_came" : len(errors),
            "timestamps" : self.now_iso()
        }

