from core_scanner.target_fingerprinting import PassiveFingerprint
import asyncio 

class RateLimitDetector:
    def __init__(self, target, list_dirs, concurrency, timeout):
        self.target = target
        self.list_of_dirs = list_dirs
        self.timeout = timeout
        self.concurrency = concurrency

    async def scan_batch(self):
        batch = []
        try:
            pf = PassiveFingerprint(target=self.target, concurrency=self.concurrency, timeout=self.timeout)
            sem = asyncio.Semaphore(self.concurrency)
            async def resp_ext(domains) :
                async with sem:
                    scan_result = await pf.scan_data(domain=domains)
                    return scan_result
            tasks = [resp_ext(d) for d in self.list_of_dirs]
            all_result = await asyncio.gather(*tasks)
            await pf.close()
            for results in all_result:
                batch.append((
                    results["status_code"],
                    results["latency_ms"],
                    results["headers"].get("Retry-After"),
                    results["headers"].get("X-RateLimit-Remaining")
                ))
            return batch
        except Exception as e:
          print(f"One Exception occured here while scanning its the rate limits scan block {e}")
          return []
    def detect_rate_limit_from_batch(self, batch):
        pass