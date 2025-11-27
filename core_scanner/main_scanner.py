# core_scanner/main_scanner.py
from ast import Try
import datetime
import asyncio
import os
import httpx

from core_scanner.target_fingerprinting import PassiveFingerprint
from .json_logger import JSONLogger

class Scanner:
    def __init__(self, target, json_file_name, json_file_path):
        if not target.endswith("/"):
            self.target = target + "/"
        self.target = target
        if(json_file_name.endswith(".json")):
            self.json_file_name = json_file_name + ".json"
        self.json_file_name = json_file_name
        os.makedirs(json_file_path, exist_ok=True)
        self.json_file_path = json_file_path
        
    async def run_scan(self, timeout, concurrency, wordlist_1, wordlist_2):
        pf = PassiveFingerprint(target=self.target, timeout=timeout, concurrency=concurrency)
        wl1 = pf.wordlist_data_extractor(wordlist_1)
        wl2 = pf.wordlist_data_extractor(wordlist_2) if wordlist_2 else []
        all_domain = wl1 + wl2 
        
        sem = asyncio.Semaphore(concurrency)
        async def req_target_domain(domain):
            async with sem:
                resp = await pf.scan_data(domain)
                return resp
        tasks = [req_target_domain(d) for d in all_domain]
        all_result = await asyncio.gather(*tasks)
        await pf.close()
        
        result = {}
        success_list = []
        error_list = []
        server_error_list = []
        redirect_list = []
        
        for scan_result in all_result:
            result[scan_result["url"]] = {
                "status_code" : scan_result["status_code"],
                "headers" : scan_result["headers"],
                "hashed_body" : scan_result["hashed_body"],
                "content_length" : scan_result["content_length"],
                "latency_ms" : scan_result["latency_ms"],
                "success" : scan_result["success"]
            }
            
            if 200 <= scan_result["status_code"] < 300:
                success_list.append(scan_result["url"])
            elif 300 <= scan_result["status_code"] < 400:
                redirect_list.append(scan_result["url"])
            elif 400 <= scan_result["status_code"] < 500:
                error_list.append(scan_result["url"])
            else :
                server_error_list.append(scan_result["url"])
            
        success_logs = {
            "message" : "Output containing the above 200 status_code",
            "result_logs" : result,
            "success_urls" : success_list
        }
        
        logger = JSONLogger(json_file_path=self.json_file_path, json_file_name=self.json_file_name)
        logger.log_to_file(success_logs)
        return {
            "message" : "The Scanning is successfully done here we have played our parts successfully",
            "success_list_urls" : len(success_list),
            "error_list_urls" : len(error_list),
            "server_error_list_urls" : len(server_error_list),
            "redirect_list" : len(redirect_list),
            "more_detailed_scanned_result" : result,
            "status_code" : 200
        }