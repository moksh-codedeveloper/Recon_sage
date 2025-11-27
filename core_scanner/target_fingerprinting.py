import asyncio
import hashlib
import httpx, asyncio
from core_scanner.aimd_currency_governor import AIMDConcurrencyDataGather
class PassiveFingerprint:
    def __init__(self, target, timeout, concurrency):
        self.target = target
        self.timeout = timeout
        self.concurrency = concurrency

    def wordlist_data_extractor(self, wordlist):
        data = []
        with open(wordlist, "r", encoding='utf-8') as f:
            for line in f:
                s = line.strip()
                if s :
                    data.append(s)
        return data

    async def scan_data(self, domain):
        subdomain_target = self.target + domain
        sem = asyncio.Semaphore(self.concurrency)
        async with sem:
            async with httpx.AsyncClient() as client:
                response = await client.get(subdomain_target)
                status_code = response.status_code
                headers = response.headers
                body_text = response.text
                latency_ms = response.elapsed.total_seconds() * 1000
                return{
                    "status_code" : status_code,
                    "headers" : headers,
                    "latency_ms" : latency_ms,
                    "response_body" : body_text,
                    "content_length" : len(response.text),
                    "cookies" : response.cookies.jar,
                    "http_version" : response.http_version,
                    "charset" : response.encoding,
                    "content_type": response.headers.get("Content-Type"),
                    "redirect_chain": [str(r.url) for r in response.history],
                    "server": response.headers.get("Server"),
                    "powered_by": response.headers.get("X-Powered-By"),
                    "cdn": response.headers.get("Via") or response.headers.get("CF-Ray"),
                    "url" : response.url,
                    "tls": {
                        "version": response.extensions.get("tls_version"),
                        "cipher": response.extensions.get("tls_cipher_suite"),
                        "peer_cert" : response.extensions.get("tls_peer_cert")
                    },
                    "set_cookies" : response.headers.get("Set-Cookie"),
                    "content_security_policy" : response.headers.get("Content-Security-Policy"),
                    "x_frame_options" : response.headers.get("X-Frame-Options"),
                    "x_content_type_options" : response.headers.get("X-Content-Type-Options"),
                    "strict_transport_security" : response.headers.get("Strict-Transport-Security")
                }
    def hash_snippet(self, body):
        if isinstance(body, bytes):
            snippet = body
            return hashlib.sha256(snippet).hexdigest()
        else:
            snippet = body
            return hashlib.sha256(snippet.encode()).hexdigest()

class WarmUpModel:
    async def benign_request(self, target, domains:list, concurrency, timeout):
        list_concurrency = []
        list_timeout = []
        if len(domains) >= 5:
            raise Exception("Bro you passed too much big domain list i just want 5 of that list this is not main scan this is the warm up scan")
        try:
            async with httpx.AsyncClient() as client:
                async def check_url(target, domains):
                    new_target = target + domains
                    resp = await client.get(new_target)
                    return resp
                for domain in domains:
                    resp = await check_url(target=target, domains=domain)
                    aimd_calculator = AIMDConcurrencyDataGather(target_url=target, status_code=resp.status_code, current_concurrency_limit=concurrency, current_timeout_limit=timeout)
                    aimd_result = aimd_calculator.aimd_calculator()
                    # return (aimd_result, aimd_calculator.data_to_dict())
                    list_concurrency.append(aimd_result["new_concurrency"])
                    list_timeout.append(aimd_result["new_timeout"])
                return {
                    "calculated_concurrency" : list_concurrency,
                    "calculated_timeout" : list_timeout
                }
        except Exception as e:
            print("There is some unexpected error with the target request", e)
            return {
                "message" : f"You are having the scan exception :- {e}",
                "success" : False
            }