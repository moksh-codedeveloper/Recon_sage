from core_scanner.target_fingerprinting import PassiveFingerprint
import asyncio 
from json_logger import JSONLogger

class RateLimitDetector:
    def __init__(self, target, list_dirs, concurrency, timeout, json_file_path, json_file_name):
        self.target = target
        self.list_of_dirs = list_dirs
        self.timeout = timeout
        self.concurrency = concurrency
        self.list_of_rate_limits_codes = [503, 403, 400, 420, 509, 444, 418, 429]
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
    
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
                if not results.get("success", False):
                    continue
                
                batch[results["url"]] = {
                    "status_code": results["status_code"],
                    "latency_ms": results["latency_ms"] or 0,
                    "retry_after_headers": results["headers"].get("Retry-After"),
                    "rate_limit_remaining_header": results["headers"].get("X-RateLimit-Remaining")
                }
            
            return batch
        
        except Exception as e:
            print(f"Exception in rate limit scan: {e}")
            return {}  # Return empty batch
    
    def detect_rate_limited(self, batch):
        all_statuses = []
        all_latencies = []
        all_retry_after_headers = []
        all_rate_limit_remaining_headers = []
        has_rate_limited = False
        all_urls_scanned = []
        
        # Extract all data
        for url, data in batch.items():
            all_statuses.append(data["status_code"])
            all_latencies.append(data["latency_ms"])
            all_retry_after_headers.append(data["retry_after_headers"])
            all_rate_limit_remaining_headers.append(data["rate_limit_remaining_header"])
            all_urls_scanned.append(url)
        
        # Check 1: Direct rate limit status codes
        if any(status in self.list_of_rate_limits_codes for status in all_statuses):
            has_rate_limited = True
        
        # Check 2: Status code transitions (200 -> 429, etc.)
        if len(all_statuses) >= 2:
            for i in range(1, len(all_statuses)):
                prev_status = all_statuses[i-1]
                curr_status = all_statuses[i]
                
                if prev_status in [200, 201, 202, 205, 206] and curr_status in self.list_of_rate_limits_codes:
                    has_rate_limited = True
                    break
        
        # Check 3: Latency spike detection
        if len(all_latencies) > 0:
            valid_latencies = [l for l in all_latencies if l > 0]
            if len(valid_latencies) >= 3:  # Need at least 3 for meaningful median
                sorted_lat = sorted(valid_latencies)
                median = sorted_lat[len(sorted_lat) // 2]
                max_lat = max(valid_latencies)
                
                if median > 0 and max_lat > median * 4:
                    has_rate_limited = True
        
        # Check 4: Retry-After header present
        if any(header is not None for header in all_retry_after_headers):
            has_rate_limited = True
        
        # Check 5: Rate limit remaining = 0
        for remaining in all_rate_limit_remaining_headers:
            if remaining is not None:
                try:
                    if int(remaining) == 0:
                        has_rate_limited = True
                        break
                except (ValueError, TypeError):
                    pass
        
        result = {
            "all_status_codes": all_statuses,
            "all_latencies": all_latencies,
            "all_retry_after_headers": all_retry_after_headers,
            "all_rate_limit_remaining_headers": all_rate_limit_remaining_headers,  # Fixed typo
            "all_urls": all_urls_scanned,
            "has_rate_limited": has_rate_limited
        }
        
        # Log to file
        rate_limit_logger = JSONLogger(
            json_file_path=self.json_file_path, 
            json_file_name=self.json_file_name
        )
        rate_limit_logger.log_to_file(result)
        
        return {
            "message": "Rate limit detection scan complete. Check JSON file for full report.",
            "result": result,
        }