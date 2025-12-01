
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
                    return {
                        "message" : "Your scan results are this and the waf detection scan has done its job",
                        "url" : str(resp.url),
                        "status_code" : resp.status_code,
                        "headers" : dict(resp.headers),
                        "latency_ms" : resp.elapsed.total_seconds(),
                        "hashed_body" : str(hashlib.sha256(resp.text.encode()).hexdigest())
                    }
        except Exception as e:
            print(f"DEBUG :- this logs are for the exception which has occured in the waf modules {e}")
            return {
                "message" : "Your scan is facing an exception and here is what i have not found",
                "url" : "",
                "status_code": 0,
                "headers" : {},
                "latency_ms" : 0,
                "hashed_body" : ""
            }