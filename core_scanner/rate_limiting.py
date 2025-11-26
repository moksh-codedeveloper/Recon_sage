import asyncio
from target_fingerprinting import PassiveFingerprint
class RateLimitDetection:
    def __init__(self, target, custom_headers, list_paths_to_test, timeout, concurrency):
        self.url = target
        self.custom_headers = custom_headers
        self.list_paths_to_test = list_paths_to_test
        self.timeout = timeout
        self.concurrency = concurrency
    
    def benign_request(self, timeout, concurrency):
        pf = PassiveFingerprint(target=self.url, timeout=timeout, concurrency=concurrency)