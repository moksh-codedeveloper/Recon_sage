import ssl
import asyncio
import hashlib
import httpx
from core_scanner.json_logger import JSONLogger
class WafDetection:
    def __init__(self, target, wordlist, json_file_path, json_file_name, timeout, concurrency) -> None:
        self.target = target
        self.wordlist = wordlist
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
        self.timeout = timeout
        self.concurrency = concurrency
        self.sem = asyncio.Semaphore(self.concurrency)

    async def fingerprint_target(self, domain) -> dict[str, object]:

        tls_version = None
        cipher_suite = None
        certificate = None

        try:
            subdirector_target = self.target + domain

            async with self.sem:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(subdirector_target)

                    # Extract TLS data safely
                    stream = resp.extensions.get("network_stream")
                    if stream:
                        ssl_object = stream.get_extra_info("ssl_object")
                        if isinstance(ssl_object, (ssl.SSLSocket, ssl.SSLObject)):
                            tls_version = ssl_object.version()
                            cipher_suite = ssl_object.cipher()
                            certificate = ssl_object.getpeercert()
                    normalize_headers = {k.lower() :  v for k,  v in dict(resp.headers).items()} 
                    return {
                        "message": "Passive WAF scan completed",
                        "url": str(resp.url),
                        "status_code": resp.status_code,
                        "headers": normalize_headers,
                        "latency_ms": resp.elapsed.total_seconds() * 1000,
                        "hashed_body": hashlib.sha256(resp.content).hexdigest(),
                        "tls_info": {
                            "tls_version": tls_version,
                            "cipher_suite": cipher_suite,
                            "certificate": certificate
                        }
                    }

        except Exception as e:
            print(f"DEBUG (waf-passive-exception): {e}")
            return {
                "message": "Scan failed due to exception",
                "url": "",
                "status_code": 0,
                "headers": {},
                "latency_ms": 0,
                "hashed_body": "",
                "error_message": str(e)
            }

    async def run_scan(self) -> dict[str, object]:
        target_result = {}
        all_statuses = []
        all_urls = []
        all_latencies = []
        
        try:
            tasks = [self.fingerprint_target(domain=domain) for domain in self.wordlist]
            results = await asyncio.gather(*tasks)

            for result in results:

                if result.get("error_message"):
                    continue
                if result["status_code"] == 0:
                    continue

                target_result[result["url"]] = {
                    "status_code": result["status_code"],
                    "hashed_body": result["hashed_body"],
                    "headers": result["headers"],
                    "latency_ms": result["latency_ms"],
                    "message": result["message"],
                    "tls_info": result["tls_info"]
                }
                all_urls.append(result["url"])
                all_statuses.append(result["status_code"])
                all_latencies.append(result["latency_ms"])

            success_logs_file = {
                "message" : "This logs are report for the success json files",
                "target_result" :  target_result
            }
            success_logger = JSONLogger(json_file_path=self.json_file_path, json_file_name=self.json_file_name)
            success_logger.log_to_file(success_logs_file)
            return {
                "message" : "The scan is complete for headers please read the report json file genearated from the scan",
                "status_codes" : all_statuses,
                "latencies_ms" : all_latencies,
                "all_urls" : all_urls
            }
        except Exception as e:
            print(f"DEBUG (run_scan exception): {e}")
            return {
                "message" : "The scan has failed unfortunately please start again with the proper network and proper permissions",
                "status_codes": [],
                "latencies_ms" : [],
                "all_urls" : [],
                "error_message" : f"The error reason message is this  :- {e}",
                "status_code" : 0
            }
    def check_for_cloudflare(self, headers:dict): # This one are not same they both are different (headers != all_matched_headers)
        cloudflare_headers = [
            'cf-ray', 
            'cf-cache-status', 
            'cf-request-id', 
            'cf-connecting-ip', 
            'cf-ipcountry', 
            'cf-warp-tag-id', 
            'cf-bgj'
            ]
        
        advanced_cloudflare_headers = [
            'cf-chl', 
            'cf-chl-bypasses', 
            'cf-chl-out', 
            'cf-mitigated', 
            'cf-turnstile', 
            'cf-challenge'
            ]
        
        all_match_headers = {} 
        
        for key, value in headers.items(): 
            if key in cloudflare_headers or key in advanced_cloudflare_headers:
                all_match_headers[key] = value
            if key == "server" and "cloudflare" in str(value).lower():
                all_match_headers[key] = value
        
        return {
            "message" : "This are some headers key which matched with there values",
            "is_it_cloudflare_waf" : True if all_match_headers != {} else False,
            "matched_headers" : all_match_headers 
        }
    
    def fastly_headers(self, headers:dict):
        fastly_headers_for_check = ['x-served-by', 'x-cached', 'x-cache-hits', 'fastly-debug-path', 'fastly-trace']
        fastly_github_specific = ['x-github-request-id', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset']
        
        all_matched_headers = {}
        for key, value in headers.items():
            if key in fastly_headers_for_check or key in fastly_github_specific:
                all_matched_headers[key] = value
            
            if key == 'server' and "github.com" in str(value).lower():
                all_matched_headers[key] = value
            
            if key == 'server' and 'varnish' in str(value).lower():
                all_matched_headers[key] = value

            if key == 'via' and '1.1 varnish' in str(value):
                all_matched_headers[key] = value
        
        return {
            "message" : "You have this result of the headers if this is present or empty",
            "is_it_fastly_waf" : True if all_matched_headers != {} else False,
            "headers" : all_matched_headers
        }
    
    def other_waf_headers(self, headers:dict):
        akamai_kona_headers = [
            'akamai-pragma-client-region', 
            'x-akamai-transformed', 
            'x-akamai-request-id', 
            'x-akamai-device-characteristics', 
            'x-true-cache-key', 
            'x-check-cacheable'
        ]
        
        imperva_headers = [
            'x-iinfo', 
            'x-cdn', 
            'x-incapsula', 
            'x-cdn-request-id'
        ]
        
        aws_headers = [
            'x-amz-cf-id',
            'x-amz-cf-pop',
            'x-amz-cf-paired-pop',
            'x-amzn-trace-id',
            'x-amzn-requestid',
            'x-amzn-errortype'
        ]
        
        all_headers_matched_akamai = {}
        all_headers_mached_imperva = {}
        all_headers_matched_aws = {}
        
        for key, values in headers.items():
            if key in imperva_headers:
                all_headers_mached_imperva[key] = values
            
            if key == 'x-cdn' and 'imperva' in str(values).lower():
                all_headers_mached_imperva[key] = values
            
            if key == 'via' and 'incapsula' in str(values).lower():
                all_headers_mached_imperva[key] = values
            
            
            if key in akamai_kona_headers:
                all_headers_matched_akamai[key] = values
            
            if key == "server" and "akamaighost" in str(values).lower():
                all_headers_matched_akamai[key] = values
             
            if key == "via" and "akamai" in str(values).lower():
                all_headers_matched_akamai[key] = values 
            
            if key in aws_headers:
                all_headers_matched_aws[key] = values
            
        return {
            "message" : "You have the summary of result of here in below" ,
            "is_it_waf_related_to_imperva" : True if all_headers_mached_imperva != {} else False,
            "is_it_waf_related_to_aws" : True if all_headers_matched_aws != {} else False,
            "is_it_waf_related_to_akamai" : True if all_headers_matched_akamai != {} else False,
            "akamai_headers" : all_headers_matched_akamai,
            "aws_headers" : all_headers_matched_aws,
            "imperva_headers" : all_headers_mached_imperva
        }