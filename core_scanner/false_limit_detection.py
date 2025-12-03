
# Class Model of the false positive detector 

import asyncio
import hashlib
import json

import httpx

from core_scanner.target_fingerprinting import PassiveFingerprint


class FalseDetector:
    def __init__(self, target, json_file_name, json_file_path, concurrency, timeout):
        self.target = target 
        self.json_file_name  = json_file_name
        self.json_file_path = json_file_path
        self.concurrency = concurrency
        self.timeout = timeout
        
    def read_scan(self, json_file_to_read) -> dict[str, object]:
        try:
            with open(json_file_to_read, "r", encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f'An exception occurred:- {e}')
            return {}
    
    async def scan_for_false_detection(self, json_file_to_read): 
        logs_of_url = self.read_scan(json_file_to_read=json_file_to_read)
        if not isinstance(logs_of_url, dict):
            raise ValueError("I think there is error has occured because the passes value is not the expected it should be the dictionary or json file but its not i don't know what the heck you are trying to pass")
        # successful_urls:list = list(logs_of_url.get("success_urls"), [])
        successful_urls = logs_of_url["success_urls"]
        if not isinstance(successful_urls, list):
            raise ValueError("The passed value or stored value in the json has no list its something else not list but we want the list for traversal")
        
        sem = asyncio.Semaphore(self.concurrency)
        async with sem :
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async def req_urls(urls):
                    resp_target = await client.get(urls)
                    hashed_body = hashlib.sha256(resp_target.text.encode()).hexdigest()
                    return {
                        "url" : resp_target.url,
                        "hashed_body" : hashed_body,
                        "status_code" : resp_target.status_code,
                        "content_length" : len(resp_target.text)
                    }
        
        tasks = [req_urls(u) for u in successful_urls]
        result = await asyncio.gather(*tasks)

        check_content_length = {}
        check_hashed_body = {}
        