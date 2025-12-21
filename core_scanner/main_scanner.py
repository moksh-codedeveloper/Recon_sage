# core_scanner/main_scanner.py
import datetime
import asyncio
import os
from .target_fingerprinting import PassiveFingerprint
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
        try:
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
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            error_log_list = {
                "message" : "Bro output containing above 400 or equal to that status codes",
                "length_of_error_list" : len(error_list),
                "error_list" : error_list
            }
            server_error_log_list = {
                "message" : "Bro output containing above 500 or equal to that status codes",
                "length_of_server_error_list" : len(server_error_list),
                "server_list" : server_error_list
            }
            error_log_file = f"error_list_from_{self.target}{timestamp}.json"
            server_error_log_file = f"server_error_list_from_{self.target}{timestamp}.json"

            logger = JSONLogger(json_file_path=self.json_file_path, json_file_name=self.json_file_name)
            error_log = JSONLogger(json_file_name=error_log_file, json_file_path=self.json_file_path)
            server_error_log = JSONLogger(json_file_path=self.json_file_path, json_file_name=server_error_log_file)
            error_log.log_to_file(error_log_list)
            server_error_log.log_to_file(server_error_log_list)
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
        except Exception as e:
          return {
              "message" : "There is some kind of exception which has been occured sadly so you might have to try again",
              "error" : e,
              "success_list_urls" : 0,
              "error_list_urls" : 0,
              "server_error_list_urls" : 0,
              "redirect_list" : 0,
              "more_detailed_scanned_result" : {},
              "status_code" : 0,
          }