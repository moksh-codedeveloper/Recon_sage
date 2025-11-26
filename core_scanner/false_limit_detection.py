import json
import os

from core_scanner.target_fingerprinting import PassiveFingerprint

class FalseDetector:
    def __init__(self, target, json_full_path, json_file_name, timeout, concurrency):
        self.target = target 
        self.json_file_name = json_file_name
        self.json_full_path = json_full_path
        self.json_file_path = os.path.join(self.json_file_name, self.json_full_path)
        self.timeout = timeout
        self.concurrency = concurrency
    
    def read_json_file(self):
        try:
            with open(self.json_file_path, "r", encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError("Your provided file is not present at the provided path please provide a proper path")

    async def scanner_module(self):
        false_positive_score = 0
        pf = PassiveFingerprint(target=self.target, timeout=self.timeout, concurrency=self.concurrency)
        common_hashed_body = {}
        common_content_length = {}
        read_json_file_result = self.read_json_file()
        success_urls = read_json_file_result.get("successfully_accessed_urls", [])
        for urls in success_urls:
            scanned_result = await pf.scan_data(domain=urls)
            response_body = scanned_result["response_body"]
            hashed_body = pf.hash_snippet(response_body)
            content_length = scanned_result["content_length"]
            if not hashed_body in common_hashed_body:
                common_hashed_body[hashed_body] = []
            else :
                common_hashed_body[hashed_body].append(scanned_result["url"])
            
            if not content_length in common_content_length:
                common_content_length[content_length] = []
            else :
                common_content_length[content_length].append(scanned_result["url"])
        false_positive_detected_hash_urls = {}
        false_positive_detected_content_url = {}
        for hashed_response, url in common_hashed_body.items():
            if len(url) > 2:
                false_positive_score += 10
                false_positive_detected_hash_urls[hashed_response] = url
            else :
                false_positive_score -= 10
        
        for content_length, url in common_content_length.items():
            if len(url) > 10:
                false_positive_score += 10
                false_positive_detected_content_url[content_length] = url
        return {
            "message" : "Here is your scan result from the false positive module",
            "false_positive_detected_from_hashes" : false_positive_detected_hash_urls,
            "false_positive_detected_from_content_length" : false_positive_detected_content_url,
            "false_positive_score" : false_positive_score
        }