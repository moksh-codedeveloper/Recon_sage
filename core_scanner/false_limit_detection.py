import asyncio
import hashlib
import json
import httpx

class FalseDetector:
    def __init__(self, target, json_file_name, json_file_path, concurrency, timeout):
        self.target = target
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
        self.concurrency = concurrency
        self.timeout = timeout

    def read_scan(self, json_file_to_read):
        try:
            with open(json_file_to_read, "r", encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading JSON: {e}")
            return {}

    async def scan_for_false_detection(self, json_file_to_read):
        logs = self.read_scan(json_file_to_read)
        if not isinstance(logs, dict):
            raise ValueError("Expected JSON dict")

        successful_urls = logs.get("success_urls", [])
        if not isinstance(successful_urls, list):
            raise ValueError("success_urls must be a list")

        sem = asyncio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(timeout=self.timeout) as client:

            async def fetch(url):
                async with sem:
                    r = await client.get(url)
                    body_hash = hashlib.sha256(r.text.encode()).hexdigest()
                    return {
                        "url": str(r.url),
                        "hash": body_hash,
                        "len": len(r.text),
                        "code": r.status_code,
                    }

            results = await asyncio.gather(*[fetch(u) for u in successful_urls])

        hash_groups = {}
        len_groups = {}

        for res in results:
            hash_groups.setdefault(res["hash"], []).append(res["url"])
            len_groups.setdefault(res["len"], []).append(res["url"])

        score = 0

        # If many URLs have identical content → false positives likely
        if any(len(urls) > 2 for urls in hash_groups.values()):
            score += 10

        if any(len(urls) > 3 for urls in len_groups.values()):
            score += 10

        return {
            "message": "False detection analysis complete.",
            "unique_hashes": len(hash_groups),
            "unique_lengths": len(len_groups),
            "false_positive_score": score
        }
