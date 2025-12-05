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
    def check_for_cloudflare(self, headers:dict):
        cloudflare_headers = ['cf-ray', 'cf-cache-status', 'cf-request-id', 'cf-connecting-ip', 'cf-ipcountry', 'cf-warp-tag-id', 'cf-bgj']
        advanced_cloudflare_headers = ['cf-chl', 'cf-chl-bypasses', 'cf-chl-out', 'cf-mitigated', 'cf-turnstile', 'cf-challenge']
        all_match_headers = {}
        for key, value in headers.items():
            if key in cloudflare_headers or key in advanced_cloudflare_headers:
                all_match_headers[key] = value
            if key == "server" and "cloudflare" in str(value).lower():
                all_match_headers[key] = value
        return {
            "message" : "This are some headers key which matched with there values",
            "matched_headers" : all_match_headers 
        }