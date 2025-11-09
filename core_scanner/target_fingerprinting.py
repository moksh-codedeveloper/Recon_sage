import asyncio, httpx

class FingerprintModels:
    def __init__(self, target, response_time, content_length, snippet, headers, status_code, tls_info, cheap_fp, cookies):
        self.target = target.strip().lower()
        self.response_time = response_time
        self.content_length = content_length
        self.snippet = snippet 
        self.headers = headers 
        self.status_codes = status_code
        self.tls_info = tls_info
        self.cheap_fp = cheap_fp
        self.cookies = cookies
        if (self.target.startswith("http://localhost") or self.target.startswith("http://127.0.0.1")):
            self.target_type = "http_localhost"
        elif self.target.startswith("http://") :
            self.target_type = "http_real_target"
        elif self.target.startswith("https://"):
            self.target_type = "real_https"
        else:
            self.target_type = "unknown"
    def scan_fingerprint(self):
        if self.target_type == "http_localhost" : 
            suggested_concurrency_limits = 100
            suggested_timeout_limits = 10
        elif self.target_type == "http_real_target" :
            suggested_concurrency_limits = 90
            suggested_timeout_limits = 10
        elif self.target_type == "real_https":
            suggested_concurrency_limits = 70
            suggested_timeout_limits = 15
        else :
            suggested_concurrency_limits = 0
            suggested_timeout_limits = 0
            warning = "Your provided target is not valid according to what model expects ex :- https://example.com/ (dont pass this as it is but be aware)"
        return {
            "target" : self.target,
            "response_time" : self.response_time,
            "content_length" : self.content_length,
            "snippet" : self.snippet,
            "headers" : self.headers,
            "status_codes" : self.status_codes,
            "tls_info" : self.tls_info,
            "cheap_fp" : self.cheap_fp,
            "cookies" : self.cookies,
            "target_type" : self.target_type,
            "suggested_concurrency_limits" : suggested_concurrency_limits,
            "suggested_timeout_limits" : suggested_timeout_limits,
            "warning" : warning or None,
        }
    def calculate_cheap_fp(self) :
        KNOWN_WAF_TOKENS = ("cloudflare", "sucuri", "incapsula", "mod_security", "akamai", "aws-waf", "f5", "imperva")

class AdvScanEngine:
    def __init__(self, target):
        self.target = target
    
    async def target_scan(self):
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(self.target)
                model = FingerprintModels(
                    target=str(resp.url),
                    response_time=resp.elapsed.total_seconds(),
                    content_length=int(resp.headers.get("content-length")) if resp.headers.get("content-length") else len(resp.content),
                    snippet=resp.content[:512],
                    headers=dict(resp.headers),
                    tls_info={},
                    cheap_fp={},
                    cookies=dict(resp.cookies),
                    status_code=resp.status_code
                )
                result = model.scan_fingerprint()
                suggested_concurrency_limits = result["suggested_concurrency_limits"]
                suggested_timeout_limits = result["suggested_timeout_limits"]
                warnings = result["warning"]
                return {
                    "warnings" : warnings,
                    "suggested_concurrency_limits" : suggested_concurrency_limits,
                    "suggested_timeout_limits" : suggested_timeout_limits
                }
            except Exception as e:
              print('An exception occurred', e)