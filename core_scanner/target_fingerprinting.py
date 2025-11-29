# core_scanner/target_fingerprinting.py
import hashlib
import httpx
from .aimd_currency_governor import AIMDConcurrencyDataGather
class PassiveFingerprint:
    def __init__(self, target, timeout, concurrency):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.concurrency = concurrency

        # GLOBAL CLIENT (reused across all requests)
        self.client = httpx.AsyncClient(
            timeout=timeout,
            limits=httpx.Limits(
                max_connections=concurrency,
                max_keepalive_connections=concurrency
            )
        )
    def hash_snippet(self, body):
        if isinstance(body, bytes):
            return hashlib.sha256(body).hexdigest()
        else:
            return hashlib.sha256(body.encode()).hexdigest()
    def wordlist_data_extractor(self, wordlist):
        with open(wordlist, "r", encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

    async def scan_data(self, domain):
        # sanitize
        if not domain.startswith("/"):
            domain = "/" + domain

        url = self.target + domain

        try:
            response = await self.client.get(url)
            body = response.text

            return {
                "success": True,
                "url": str(response.url),
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "latency_ms": response.elapsed.total_seconds() * 1000,
                "response_body": body,
                "hashed_body": hashlib.sha256(body.encode()).hexdigest(),
                "content_length": len(body)
            }

        except Exception as e:
            return {
                "success": False,
                "url": url,
                "status_code": 0,
                "error": str(e),
                "headers": {},
                "latency_ms": None,
                "response_body": "",
                "hashed_body": None,
                "content_length": 0
            }

    async def close(self):
        await self.client.aclose()

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
                "calculated_concurrency" : [],
                "calculated_timeout" : []
            }