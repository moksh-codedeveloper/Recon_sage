import asyncio
import httpx
class RateLimitDetection:
    def __init__(self, target, custom_headers, list_paths_to_test, timeout, concurrency):
        self.url = target
        self.custom_headers = custom_headers
        self.list_paths_to_test = list_paths_to_test
        self.timeout = timeout
        self.concurrency = concurrency
    
    async def bening_request(self):
        semaphore = asyncio.Semaphore(self.concurrency)
        async with semaphore:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.url)
                