import hashlib
import httpx
class PassiveFingerprint:
    def __init__(self, target, timeout):
        self.target = target
        self.timeout = timeout

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
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(subdomain_target)
            return response
        except Exception as e:
            return {
                "message" : f"There is one Exception which has occurred here!{e}"
            }

    def hash_snippet(self, body, length=300):
        if isinstance(body, bytes):
            snippet = body[:length]
            return hashlib.sha256(snippet).hexdigest()
        else:
            snippet = body[:length]
            return hashlib.sha256(snippet.encode()).hexdigest()