import datetime
import ssl
import asyncio
import hashlib
import httpx
from core_scanner.json_logger import JSONLogger


class WafDetection:
    def __init__(self, target, wordlist, json_file_path, json_file_name, timeout, concurrency):
        self.target = target.rstrip("/")
        self.wordlist = wordlist
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
        self.timeout = timeout
        self.concurrency = concurrency
        self.sem = asyncio.Semaphore(self.concurrency)

    async def fingerprint_target(self, domain):
        """Scan single endpoint and extract WAF fingerprints"""
        
        if not domain.startswith("/"):
            domain = "/" + domain
        
        url = self.target + domain

        try:
            async with self.sem:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(url)

                    tls_info = self._extract_tls_info(resp)
                    normalized_headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                    
                    return {
                        "success": True,
                        "url": str(resp.url),
                        "status_code": resp.status_code,
                        "headers": normalized_headers,
                        "latency_ms": resp.elapsed.total_seconds() * 1000,
                        "hashed_body": hashlib.sha256(resp.content).hexdigest(),
                        "tls_info": tls_info
                    }

        except Exception as e:
            print(f"⚠️ WAF scan failed for {domain}: {e}")
            return {
                "success": False,
                "url": url,
                "status_code": 0,
                "headers": {},
                "latency_ms": 0,
                "hashed_body": "",
                "tls_info": {},
                "error": str(e)
            }

    def _extract_tls_info(self, response):
        """Extract TLS/SSL information from response"""
        try:
            stream = response.extensions.get("network_stream")
            if not stream:
                return {}

            ssl_object = stream.get_extra_info("ssl_object")
            if not isinstance(ssl_object, (ssl.SSLSocket, ssl.SSLObject)):
                return {}

            return {
                "tls_version": ssl_object.version(),
                "cipher_suite": ssl_object.cipher(),
                "certificate": ssl_object.getpeercert()
            }
        except Exception:
            return {}

    async def run_scan(self):
        """Scan all endpoints and detect WAFs"""
        target_result = {}
        all_statuses = []
        all_urls = []
        all_latencies = []
        waf_detection_logs = {}  # Simple: URL -> detection result
        
        try:
            # Scan all domains
            tasks = [self.fingerprint_target(domain) for domain in self.wordlist]
            results = await asyncio.gather(*tasks)

            # Process results
            for result in results:
                if not result.get("success", False):
                    continue

                url = result["url"]
                headers = result["headers"]
                
                # Detect WAF (your Big 5)
                waf_detection = self.detect_waf(headers)
                
                # Store scan data
                target_result[url] = {
                    "status_code": result["status_code"],
                    "hashed_body": result["hashed_body"],
                    "headers": headers,
                    "latency_ms": result["latency_ms"],
                    "tls_info": result["tls_info"]
                }
                
                # Store WAF detection separately (simple dict)
                waf_detection_logs[url] = waf_detection
                
                all_urls.append(url)
                all_statuses.append(result["status_code"])
                all_latencies.append(result["latency_ms"])

            # Log to file
            log_data = {
                "message": "WAF detection scan complete",
                "total_scanned": len(all_urls),
                "target_result": target_result,
                "waf_detection_logs": waf_detection_logs
            }
            
            logger = JSONLogger(
                json_file_path=self.json_file_path,
                json_file_name=self.json_file_name
            )
            logger.log_to_file(log_data)
            
            return {
                "message": "WAF scan complete. Check JSON report for details.",
                "success": True,
                "total_scanned": len(all_urls),
                "status_codes": all_statuses,
                "latencies_ms": all_latencies,
                "all_urls": all_urls,
                "waf_detection_logs": waf_detection_logs
            }
        
        except Exception as e:
            print(f"❌ WAF scan failed: {e}")
            return {
                "message": "WAF scan failed",
                "success": False,
                "status_codes": [],
                "latencies_ms": [],
                "all_urls": [],
                "error": str(e)
            }

    def detect_waf(self, headers):
        """
        Detect WAF from headers
        Returns simple dict with all detection results
        """
        cloudflare = self.check_cloudflare(headers)
        fastly = self.check_fastly(headers)
        other_wafs = self.check_other_wafs(headers)
        
        # Check if ANY WAF detected
        waf_detected = (
            cloudflare["is_cloudflare"] or
            fastly["is_fastly"] or
            other_wafs["is_akamai"] or
            other_wafs["is_imperva"] or
            other_wafs["is_aws"]
        )
        
        return {
            "waf_detected": waf_detected,
            "cloudflare": cloudflare,
            "fastly": fastly,
            "akamai": other_wafs["akamai"],
            "imperva": other_wafs["imperva"],
            "aws": other_wafs["aws"]
        }

    def check_cloudflare(self, headers):
        """Detect Cloudflare WAF"""
        cf_headers = [
            'cf-ray', 'cf-cache-status', 'cf-request-id',
            'cf-connecting-ip', 'cf-ipcountry', 'cf-warp-tag-id', 'cf-bgj'
        ]
        
        cf_advanced = [
            'cf-chl', 'cf-chl-bypasses', 'cf-chl-out',
            'cf-mitigated', 'cf-turnstile', 'cf-challenge'
        ]
        
        matched = {}
        
        for key, value in headers.items():
            if key in cf_headers or key in cf_advanced:
                matched[key] = value
            elif key == "server" and "cloudflare" in str(value).lower():
                matched[key] = value
        
        return {
            "is_cloudflare": bool(matched),
            "matched_headers": matched
        }
    
    def check_fastly(self, headers):
        """Detect Fastly CDN/WAF"""
        fastly_headers = [
            'x-served-by', 'x-cached', 'x-cache-hits',
            'fastly-debug-path', 'fastly-trace'
        ]
        
        fastly_github = [
            'x-github-request-id', 'x-ratelimit-limit',
            'x-ratelimit-remaining', 'x-ratelimit-reset'
        ]
        
        matched = {}
        
        for key, value in headers.items():
            if key in fastly_headers or key in fastly_github:
                matched[key] = value
            elif key == 'server' and "github.com" in str(value).lower():
                matched[key] = value
            elif key == 'server' and 'varnish' in str(value).lower():
                matched[key] = value
            elif key == 'via' and '1.1 varnish' in str(value).lower():
                matched[key] = value
        
        return {
            "is_fastly": bool(matched),
            "matched_headers": matched
        }
    
    def check_other_wafs(self, headers):
        """Detect Akamai, Imperva, AWS WAFs"""
        
        akamai_headers = [
            'akamai-pragma-client-region', 'x-akamai-transformed',
            'x-akamai-request-id', 'x-akamai-device-characteristics',
            'x-true-cache-key', 'x-check-cacheable'
        ]
        
        imperva_headers = [
            'x-iinfo', 'x-cdn', 'x-incapsula', 'x-cdn-request-id'
        ]
        
        aws_headers = [
            'x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-cf-paired-pop',
            'x-amzn-trace-id', 'x-amzn-requestid', 'x-amzn-errortype'
        ]
        
        akamai_matched = {}
        imperva_matched = {}
        aws_matched = {}
        
        for key, value in headers.items():
            value_lower = str(value).lower()
            
            # Akamai
            if key in akamai_headers:
                akamai_matched[key] = value
            elif key == "server" and "akamaighost" in value_lower:
                akamai_matched[key] = value
            elif key == "via" and "akamai" in value_lower:
                akamai_matched[key] = value
            
            # Imperva
            if key in imperva_headers:
                imperva_matched[key] = value
            elif key == 'x-cdn' and 'imperva' in value_lower:
                imperva_matched[key] = value
            elif key == 'via' and 'incapsula' in value_lower:
                imperva_matched[key] = value
            
            # AWS
            if key in aws_headers:
                aws_matched[key] = value
        
        return {
            "is_akamai": bool(akamai_matched),
            "is_imperva": bool(imperva_matched),
            "is_aws": bool(aws_matched),
            "akamai": {
                "matched_headers": akamai_matched
            },
            "imperva": {
                "matched_headers": imperva_matched
            },
            "aws": {
                "matched_headers": aws_matched
            }
       }

class ActiveWafScan:
    def __init__(self, timeout, concurrency, target:str, json_file_name:str, json_file_path:str, wordlist:list, headers:dict, params:str):
        self.target = target
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
        if len(wordlist) <= 5:
            self.wordlist = wordlist
        else :
            self.wordlist = wordlist[:5]
        self.headers = headers
        self.params = params
        self.concurrency = concurrency
        self.timeout = timeout
        self.sem = asyncio.Semaphore(self.concurrency)

    async def probe_target(self, domain):
        try:
          async with httpx.AsyncClient(timeout=self.timeout) as client:
            sub_target = self.target + domain
            resp = await client.get(sub_target, headers=self.headers, params=self.params)
            return {
                "url" : str(resp.url), 
                "headers" : dict(resp.headers),
                "status_code" : resp.status_code,
                "latency_ms" : resp.elapsed.total_seconds(),
                "timestamps" : datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            }
        except Exception as e:
            print(f"[-]Exceptions occured here :- {e}")
            return {
                "url" : "",
                "headers" : {},
                "status_code" : 0,
                "latency_ms" : 0,
                "timestamps" : datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
                "message" : f"There is some error which has occured here suggestion solve this and restart the scanning :- {e}"
            }
    
    async def  harmless_request(self, domain):
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                sub_target = self.target + domain
                resp = await client.get(sub_target)
                return {
                    "message" : "This scan batch got successful",
                    "status_code" : resp.status_code,
                    "url" : str(resp.url),
                    "headers" : dict(resp.headers),
                    "tls_info" : {},
                    "latency_ms" : resp.elapsed.total_seconds(),
                    "timestamps" :  datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                }
        except Exception as e:
            print(f"DEBUG there is scan exception in the harmless request in here :- {e}")
            return {
                "message" : f"there is exception here in the harmless request method :- {e}",
                "url" : "",
                "headers" : {},
                "status_code" : 0,
                "latency_ms" : 0,
                "timestamps" : datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            }
    async def run_scan(self, concurrency, headers, timeout, params):
        target_result = {}
        status_code_for_waf = [406, 419, 420,  429, 444, 450, 494, 499, 510, 521, 522, 523, 525, 526, 530]
        try:
            # target fingerprinting of the on-purpose harmful request (To see the server reaction)
            async with self.sem:
                tasks = [self.probe_target(domain) for domain in self.wordlist]
                all_result = await asyncio.gather(*tasks)
                for result in all_result:
                    if result["status_code"] in status_code_for_waf:
                        target_result[result["url"]] = {
                            "status_code" : result["status_code"],
                            "headers" : result["headers"],
                            "latency_info" : result["latency_ms"],
                            "timestamps" : result["timestamps"]
                        }
            # servers reaction on the harmless request and tls checking on this request for waf and cdns 
            async with self.sem:
                tasks = [self.harmless_request(domain) for domain in self.wordlist]
                all_result  = await asyncio.gather(*tasks)
        except Exception as e:
          print(f'There is exception in the run_scan in the method of the active waf :- {e}')