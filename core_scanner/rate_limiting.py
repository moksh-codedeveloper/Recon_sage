from core_scanner.target_fingerprinting import PassiveFingerprint
import asyncio 

from json_logger import JSONLogger

class RateLimitDetector:
    def __init__(self, target, list_dirs, concurrency, timeout):
        self.target = target
        self.list_of_dirs = list_dirs
        self.timeout = timeout
        self.concurrency = concurrency
    
    async def scan_batch(self):
        batch = {}
        
        try:
            pf = PassiveFingerprint(
                target=self.target, 
                concurrency=self.concurrency, 
                timeout=self.timeout
            )
            sem = asyncio.Semaphore(self.concurrency)
            
            async def resp_ext(domain):
                async with sem:
                    scan_result = await pf.scan_data(domain=domain)
                    return scan_result
            
            tasks = [resp_ext(d) for d in self.list_of_dirs]
            all_result = await asyncio.gather(*tasks)
            await pf.close()
            
            for results in all_result:
                # Skip failed requests (optional - keep if you want to track failures)
                if not results.get("success", False):
                    continue
                
                batch[results["url"]] = {
                    "status_code": results["status_code"],
                    "latency_ms": results["latency_ms"] or 0,  # Handle None
                    "retry_after_headers": results["headers"].get("Retry-After"),
                    "rate_limit_remaining_header": results["headers"].get("X-RateLimit-Remaining")
                }
            
            return batch
        
        except Exception as e:
            print(f"Exception in rate limit scan: {e}")
            return {
                "status_code" : 0,
                "latency_ms" : 0,
                "retry_after_headers" : 0,
                "rate_limit_remaining_header" : 0,
                "success" : False,
                "error" : e
            }
    
    def is_rate_limited(self):
        pass