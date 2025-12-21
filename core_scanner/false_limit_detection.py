import asyncio
import hashlib
import json
import httpx
from .json_logger import JSONLogger
class FalseDetector:
    def __init__(self, target, json_file_name, json_file_path, concurrency, timeout):
        self.target = target
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
        self.concurrency = concurrency
        self.timeout = timeout

    def read_json_file(self, json_file_to_read) -> dict[str, object]:
        try:
            with open(json_file_to_read, "r", encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"This is exception from the read json method from the false detector and here is the message {e}")
            return {}
    async def execute_scan(self, json_file_to_read):
        all_common_urls_from_hashed_body = []
        all_common_urls_from_content_length = []
        common_hashed_body = {}
        common_content_length = {}
        try:
            file_json = dict(self.read_json_file(json_file_to_read))
            success_urls = file_json.get("success_urls")
            if not isinstance(success_urls, list):
                raise ValueError("The passed json file has the success urls but not in the array form which is expected here and also needed by this module")
            
            sem = asyncio.Semaphore(self.concurrency)
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async def fetch(target) :
                    async with sem:
                        resp = await client.get(url=target)
                        return {
                            "status_code" : resp.status_code, 
                            "urls" : str(resp.url),
                            "hashed_body" : hashlib.sha256(resp.text.encode()).hexdigest(),
                            "content_length": len(resp.text)
                        }
                fetch_result = await asyncio.gather(*[fetch(url) for url in success_urls])
            for key in fetch_result:
                if key["hashed_body"] not in common_hashed_body:
                    common_hashed_body[key["hashed_body"]] = []
                common_hashed_body[key["hashed_body"]].append(key["urls"])
            for content_length in fetch_result:
                if content_length["content_length"] not in common_content_length:
                    common_content_length[content_length["content_length"]] = []
                common_content_length[content_length["content_length"]].append(content_length["urls"])
            
            for urls in common_hashed_body.values():
                if len(urls) > 2:
                    all_common_urls_from_hashed_body.append(urls)
            
            for urls in common_content_length.values():
                if len(urls) >= 11:
                    all_common_urls_from_content_length.append(urls)
            false_urls_logger = JSONLogger(json_file_name=self.json_file_name, json_file_path=self.json_file_path)
            false_urls_logs = {
                "message" : "This is the detailed report on what are the content based false positive and content length is included too",
                "length_of_hashed_based_false" : len(all_common_urls_from_hashed_body),
                "length_of_content_length_based_false" : len(all_common_urls_from_content_length),
                "detailed_urls_from_common_hashed_body" : all_common_urls_from_hashed_body,
                "detailed_urls_from_content_length_body" : all_common_urls_from_content_length
            }
            false_urls_logger.log_to_file(false_urls_logs)
            return{
                "length_of_hashed_body_common_urls": len(all_common_urls_from_hashed_body),
                "length_of_content_length_common_urls" : len(all_common_urls_from_content_length),
                "message" : "For more detailed summary on what exact urls are false positive please visit the json logs and carry on your research on them"
            }
        except Exception as e:
            print("There is some exception which has occured in the scan part of the false detector", e)
            return {
                "length_of_hashed_body_common_urls" : 0,
                "length_of_content_length_common_urls": 0,
                "message" : f"There is some issues with either the server side or the urls request please see the detailed errors and solve it by either restarting or check networks :- {e}"
            }