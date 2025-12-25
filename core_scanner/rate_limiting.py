# core_scanner/rate_limiting.py

from core_scanner.target_fingerprinting import PassiveFingerprint
import asyncio, statistics 
from core_scanner.json_logger import JSONLogger

class RateLimitDetection:
    def __init__(self, target:str, json_file_path:str, json_file_name:str, timeout:int, concurrency:int, user_paths:list):
        self.target = target
        self.concurrency = concurrency
        self.timeout = timeout
        self.json_file_path = json_file_path
        self.json_file_name = json_file_name
        self.user_paths = user_paths
    
    async def scan_batch(self, domain):
        try:
            pf = PassiveFingerprint(
                target=self.target, 
                concurrency=self.concurrency,
                timeout=self.timeout
            )
            scan_result = await pf.scan_data(domain=domain)
            return{
                "message" : "This is the scan result from the batch :-",
                "target" : scan_result["url"],
                "latency_ms" : scan_result["latency_ms"],
                "headers" : scan_result["headers"],
                "content_length" : scan_result["content_length"],
                "status_code" : scan_result["status_code"]
            }
        except Exception as e:
            print(f"There is an exception here {e}")
            return {
                "message" : f"There is an exception here see this message {e}",
                "target" : "",
                "status_code" : 0,
                "content_length" : 0,
                "hash_snippet" : "",
                "latency_ms" : 0
            }
    
    def detect_status_code_rate_limit(self, all_status_code:list):
        if not all_status_code:
            return {}
        
        rate_limit_status_codes = [429, 420, 402, 403, 503]
        rate_limit_score = 0
        rate_limited_status_codes = []
        for status_code in all_status_code:
            if status_code in rate_limit_status_codes:
                rate_limit_score += 20
                rate_limited_status_codes.append(status_code)
        return {
            "message" : "This the sofisticated scan summary of the rate limit status codes analysis",
            "rate_limit_score" : rate_limit_score,
            "rate_limited_status_code" : rate_limited_status_codes
        }

    def detect_latency_rate_limited(self, all_latency_ms:list):
        if not all_latency_ms:
            return {}
        
        if len(all_latency_ms) < 3:
            return {}

        rate_limited_latency_ms = []
        latency_rate_limited_scores = 0
        
        for lat_ms in all_latency_ms:
            if lat_ms >= 1000:
                latency_rate_limited_scores += 50
                rate_limited_latency_ms.append(lat_ms)
            
        # Spike detection :
        lat_mean = statistics.mean(all_latency_ms)
        lat_stdev = statistics.stdev(all_latency_ms)
        
        thresholds = lat_mean + (lat_stdev * 3)
        lats_spike_detected = [x for x in all_latency_ms if x > thresholds]
        
        # latency increasing trend :-
        latency_increasing_trend_score = 0
        latency_decreasing_trend_score  = 0
        for i in range(1, len(all_latency_ms)):
            if all_latency_ms[i-1] < all_latency_ms[i]:
                latency_increasing_trend_score += 10
            
            if all_latency_ms[i-1] > all_latency_ms[i]:
                latency_decreasing_trend_score += 10
            
        if len(lats_spike_detected) > 1:
            latency_rate_limited_scores += 50

        mathematical_info = {
            "mean" : lat_mean,
            "stdev" : lat_stdev
        }

        latency_trends_score = {
            "latency_increasing_score" : latency_increasing_trend_score,
            "latency_decreasing_score" : latency_decreasing_trend_score,
            "latency_rate_limited_score" : latency_rate_limited_scores
        }
        actual_latency_detected = {
            "rate_limted_latency_ms" : rate_limited_latency_ms,
            "lats_spike_detected" : lats_spike_detected
        }
        return {
            "message" : "This is the analysis result from the observation from the scans here is the detailed info",
            "mathematical_info" : mathematical_info,
            "latency_trends_score" : latency_trends_score,
            "actual_latency_detected" : actual_latency_detected
        }
    async def main_scan(self):
        all_headers = []
        all_status_codes  = []
        all_latencies_ms = []
        try:
            tasks = [self.scan_batch(d) for d in self.user_paths]
            all_result = await asyncio.gather(*tasks)
            for result in all_result:
                all_headers.append(result["headers"])
                all_latencies_ms.append(result["latency_ms"])
                all_status_codes.append(result["status_code"])
            analysis_latency_ms = self.detect_latency_rate_limited(all_latencies_ms)
            analysis_status_codes = self.detect_status_code_rate_limit(all_status_code=all_status_codes)
            logger_obj = JSONLogger(json_file_name=self.json_file_name, json_file_path=self.json_file_path)
            log_to_file = {
                "analysis_latency_ms" : analysis_latency_ms,
                "analysis_status_code" : analysis_status_codes,
                "all_headers" : all_headers,
                "all_status_code": all_status_codes,
                "all_latency_ms" : all_latencies_ms
            }
            
            logger_obj.log_to_file(logs=log_to_file)

            return {
                "message" : "Main scan is completed and here are the result lets see what we have here",
                "analysis_from_both_detectors" : {
                    "analysis_latency_ms" : analysis_latency_ms,
                    "analysis_status_code" : analysis_status_codes
                }
            }
        except Exception as e:
            print("There is one exception here :- ", e)
            return {
                "message" : f"There is one exception here is the message of the exception :- {e}",
                "analysis_from_both_detectors" : {
                    "analysis_latency_ms" : {},
                    "analysis_status_code": {}
                }
            }