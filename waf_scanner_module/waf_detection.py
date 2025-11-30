
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
    
    def wordlist_words_extractor(self) -> list[str]:
        data = []
        for words in self.wordlist:
            data.append(words)
        return data
    
    async def fingerprint_target(self, domain):
        try:
            subdirector_target = self.target + domain
            sem = asyncio.Semaphore(self.concurrency)
            async with sem:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(subdirector_target)
                    success_logs = {
                        "url" : resp.url,
                        "status_code" : resp.status_code,
                        "headers" : resp.headers,
                        "latency_ms" : resp.elapsed.total_seconds(),
                        "hashed_body" : hashlib.sha256(resp.text.encode()).hexdigest()
                    }
                    return success_logs
        except Exception as e:
            print(f"DEBUG :- this logs are for the exception which has occured in the waf modules {e}")