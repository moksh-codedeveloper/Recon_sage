import asyncio
import datetime
import hashlib
import httpx
class RateLimitDetection:
    def __init__(self, target, custom_headers, list_paths_to_test, timeout, concurrency):
        self.url = target
        self.custom_headers = custom_headers
        self.list_paths_to_test = list_paths_to_test
        self.timeout = timeout
        self.concurrency = concurrency
    
    def hash_snippet(self, body, length=300):
        """Hash only first N bytes/chars depending on input type."""
        if isinstance(body, bytes):                # bytes → raw
            snippet = body[:length]
            return hashlib.sha256(snippet).hexdigest()
        else:                                      # str → encode
            snippet = body[:length]
            return hashlib.sha256(snippet.encode()).hexdigest()

    async def bening_request(self):
        all_domain = []
        for domain in self.list_paths_to_test :
            s = domain.strip()
            if s :
                target = self.url + domain
                all_domain.append(target)
        result = {}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for domain in all_domain:
                response = await client.get(domain)
                
                status_code = response.status_code
                headers = response.headers
                response_text = response.text 
                response_bytes = response.content 
                
                hashed_text = self.hash_snippet(response_text)
                hashed_bytes =  self.hash_snippet(response_bytes)
                
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%D-%M-%Y")
                result[timestamp]