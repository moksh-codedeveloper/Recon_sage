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
        domains = []
        for paths_list in self.list_paths_to_test :
            full_domain = self.url + paths_list
            domains.append(full_domain)
        print("Bening request are preparing to start firing the request on the targets......")
        async with semaphore:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for domain  in domains :
                    response = await client.get(domain)
                    resp_headers = response.headers
                    resp_status_code = response.status_code 
                                   