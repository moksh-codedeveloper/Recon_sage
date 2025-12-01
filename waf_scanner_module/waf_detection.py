import ssl
import asyncio
import hashlib
import httpx

class WafDetection:
    def __init__(self, target, wordlist, json_file_path, json_file_name, timeout, concurrency) -> None:
        self.target = target
        self.wordlist = wordlist
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
        self.timeout = timeout
        self.concurrency = concurrency
        self.sem = asyncio.Semaphore(self.concurrency)

    def wordlist_words_extractor(self) -> list[str]:
        return list(self.wordlist)

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

                    return {
                        "message": "Passive WAF scan completed",
                        "url": str(resp.url),
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
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

    async def run_scan(self) -> dict[str, dict]:
        wordlist_data = self.wordlist_words_extractor()
        target_result = {}

        try:
            tasks = [self.fingerprint_target(domain=domain) for domain in wordlist_data]
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

            return target_result

        except Exception as e:
            print(f"DEBUG (run_scan exception): {e}")
            return {}
