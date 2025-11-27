import json
import os
import asyncio
from urllib.parse import urlparse

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
            raise FileNotFoundError(
                "Provided JSON file not found. Check your path again."
            )

    async def scanner_module(self):
        false_positive_score = 0
        pf = PassiveFingerprint(self.target, self.timeout, self.concurrency)

        read_json_file_result = self.read_json_file()
        success_urls = read_json_file_result.get("successfully_accessed_urls", [])

        # -------------------------------
        # Convert full URLs → paths only
        # -------------------------------
        domains_to_scan = []
        for full_url in success_urls:
            parsed = urlparse(full_url)
            path = parsed.path if parsed.path else "/"
            domains_to_scan.append(path)

        # Shared maps
        common_hashed_body = {}
        common_content_length = {}

        # -------------------------------
        # REAL CONCURRENCY + SHARED CLIENT
        # -------------------------------
        sem = asyncio.Semaphore(self.concurrency)

        async def bounded_false_scan(domain):
            async with sem:
                return await pf.scan_data(domain)

        tasks = [bounded_false_scan(domain) for domain in domains_to_scan]
        scan_results = await asyncio.gather(*tasks)

        # -------------------------------
        # Process results
        # -------------------------------
        for scanned_result in scan_results:
            url = scanned_result["url"]
            body = scanned_result.get("response_body", "")
            hashed_body = pf.hash_snippet(body)
            content_length = scanned_result.get("content_length", 0)

            # HASH BUCKETS
            if hashed_body not in common_hashed_body:
                common_hashed_body[hashed_body] = [url]
            else:
                common_hashed_body[hashed_body].append(url)

            # CONTENT LENGTH BUCKETS
            if content_length not in common_content_length:
                common_content_length[content_length] = [url]
            else:
                common_content_length[content_length].append(url)

        # -------------------------------
        # Detect false positives
        # -------------------------------
        false_positive_detected_hash_urls = {}
        false_positive_detected_content_url = {}

        for hashed_response, urls in common_hashed_body.items():
            if len(urls) >= 3:   # threshold tuned
                false_positive_score += 10
                false_positive_detected_hash_urls[hashed_response] = urls

        for length, urls in common_content_length.items():
            if len(urls) >= 5:   # threshold tuned
                false_positive_score += 10
                false_positive_detected_content_url[length] = urls

        # -------------------------------
        # Final return
        # -------------------------------
        return {
            "message": "False-positive analysis completed.",
            "false_positive_detected_from_hashes": false_positive_detected_hash_urls,
            "false_positive_detected_from_content_length": false_positive_detected_content_url,
            "false_positive_score": false_positive_score,
        }
