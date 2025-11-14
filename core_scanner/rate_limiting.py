import asyncio
import datetime
import hashlib
import httpx
import statistics

class RateLimitDetection:
    def __init__(self, target, custom_headers, list_paths_to_test, timeout, concurrency):
        self.url = target
        self.custom_headers = custom_headers
        self.list_paths_to_test = list_paths_to_test
        self.timeout = timeout
        self.concurrency = concurrency
    
    def hash_snippet(self, body, length=300):
        if isinstance(body, bytes):
            snippet = body[:length]
            return hashlib.sha256(snippet).hexdigest()
        else:
            snippet = body[:length]
            return hashlib.sha256(snippet.encode()).hexdigest()

    async def benign_request(self, samples_per_path=5):
        results = {}

        # Prepare domains
        domains = []
        for domain in self.list_paths_to_test:
            s = domain.strip()
            if s:
                domains.append(self.url + s)

        async with httpx.AsyncClient(timeout=self.timeout, headers=self.custom_headers) as client:
            for domain in domains:
                latency_list = []
                hash_list = []
                status_list = []
                
                # Collect 3–5 samples per domain
                for _ in range(samples_per_path):
                    response = await client.get(domain)

                    status_code = response.status_code
                    headers = dict(response.headers)
                    response_text = response.text
                    response_bytes = response.content
                    cookies = dict(response.cookies)

                    latency_ms = response.elapsed.total_seconds() * 1000
                    latency_list.append(latency_ms)

                    # Hash both
                    hash_text = self.hash_snippet(response_text)
                    hash_bytes = self.hash_snippet(response_bytes)

                    # Store hashes for stability
                    hash_list.append(hash_text)
                    status_list.append(status_code)

                    # Sleep to avoid spike
                    await asyncio.sleep(0.5)

                # Compute baseline metrics
                median_latency = statistics.median(latency_list)
                p95_latency = statistics.quantiles(latency_list, n=100)[94]

                # Mode (most common)
                status_mode = max(set(status_list), key=status_list.count)
                hash_mode = max(set(hash_list), key=hash_list.count)

                timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

                results[domain] = {
                    "domain": domain,
                    "latency": {
                        "samples": latency_list,
                        "median": median_latency,
                        "p95": p95_latency
                    },
                    "status": {
                        "samples": status_list,
                        "mode": status_mode
                    },
                    "hash": {
                        "samples": hash_list,
                        "mode": hash_mode
                    },
                    "timestamp": timestamp
                }

        return results
