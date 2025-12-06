import ssl
import asyncio
import hashlib
import httpx
from core_scanner.json_logger import JSONLogger


class WafDetection:
    def __init__(self, target, wordlist, json_file_path, json_file_name, timeout, concurrency):
        self.target = target.rstrip("/")  # Remove trailing slash
        self.wordlist = wordlist
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
        self.timeout = timeout
        self.concurrency = concurrency
        self.sem = asyncio.Semaphore(self.concurrency)

    async def fingerprint_target(self, domain):
        """Scan single endpoint and extract WAF fingerprints"""
        
        # Ensure domain starts with /
        if not domain.startswith("/"):
            domain = "/" + domain
        
        url = self.target + domain

        try:
            async with self.sem:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(url)

                    # Extract TLS info
                    tls_info = self._extract_tls_info(resp)
                    
                    # Normalize headers to lowercase
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
        """Scan all endpoints and aggregate results"""
        target_result = {}
        all_statuses = []
        all_urls = []
        all_latencies = []
        
        try:
            # Scan all domains concurrently
            tasks = [self.fingerprint_target(domain) for domain in self.wordlist]
            results = await asyncio.gather(*tasks)

            # Process results
            for result in results:
                # Skip failed requests
                if not result.get("success", False):
                    continue

                url = result["url"]
                target_result[url] = {
                    "status_code": result["status_code"],
                    "hashed_body": result["hashed_body"],
                    "headers": result["headers"],
                    "latency_ms": result["latency_ms"],
                    "tls_info": result["tls_info"]
                }
                
                all_urls.append(url)
                all_statuses.append(result["status_code"])
                all_latencies.append(result["latency_ms"])

            # Log to file
            log_data = {
                "message": "WAF detection scan complete",
                "total_scanned": len(all_urls),
                "target_result": target_result
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
                "all_urls": all_urls
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
        Detect WAF from headers (master method)
        Returns combined detection results
        """
        cloudflare = self.check_cloudflare(headers)
        fastly = self.check_fastly(headers)
        others = self.check_other_wafs(headers)
        
        # Determine if ANY WAF detected
        waf_detected = (
            cloudflare["is_cloudflare"] or
            fastly["is_fastly"] or
            others["is_akamai"] or
            others["is_imperva"] or
            others["is_aws"]
        )
        
        return {
            "waf_detected": waf_detected,
            "cloudflare": cloudflare,
            "fastly": fastly,
            "akamai": others["akamai"],
            "imperva": others["imperva"],
            "aws": others["aws"]
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
            "matched_headers": matched,
            "confidence": "high" if any(h in matched for h in cf_advanced) else "medium"
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
        
        # Akamai signatures
        akamai_headers = [
            'akamai-pragma-client-region', 'x-akamai-transformed',
            'x-akamai-request-id', 'x-akamai-device-characteristics',
            'x-true-cache-key', 'x-check-cacheable'
        ]
        
        # Imperva signatures
        imperva_headers = [
            'x-iinfo', 'x-cdn', 'x-incapsula', 'x-cdn-request-id'
        ]
        
        # AWS signatures
        aws_headers = [
            'x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-cf-paired-pop',
            'x-amzn-trace-id', 'x-amzn-requestid', 'x-amzn-errortype'
        ]
        
        akamai_matched = {}
        imperva_matched = {}
        aws_matched = {}
        
        for key, value in headers.items():
            value_lower = str(value).lower()
            
            # Akamai detection
            if key in akamai_headers:
                akamai_matched[key] = value
            elif key == "server" and "akamaighost" in value_lower:
                akamai_matched[key] = value
            elif key == "via" and "akamai" in value_lower:
                akamai_matched[key] = value
            
            # Imperva detection
            if key in imperva_headers:
                imperva_matched[key] = value
            elif key == 'x-cdn' and 'imperva' in value_lower:
                imperva_matched[key] = value
            elif key == 'via' and 'incapsula' in value_lower:
                imperva_matched[key] = value
            
            # AWS detection
            if key in aws_headers:
                aws_matched[key] = value
        
        return {
            "is_akamai": bool(akamai_matched),
            "is_imperva": bool(imperva_matched),
            "is_aws": bool(aws_matched),
            "akamai": {
                "matched_headers": akamai_matched,
                "confidence": "high" if len(akamai_matched) >= 2 else "medium"
            },
            "imperva": {
                "matched_headers": imperva_matched,
                "confidence": "high" if 'x-iinfo' in imperva_matched else "medium"
            },
            "aws": {
                "matched_headers": aws_matched,
                "confidence": "high" if 'x-amz-cf-id' in aws_matched else "medium"
            }
        }