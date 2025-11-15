import hashlib
import httpx, datetime
from json_logger import JSONLogger
from aimd_currency_governor import AIMDConcurrencyDataGather

class PassiveFingerprint:
    def __init__(self, target, wordlist_path_1, wordlist_path_2, timeout):
        self.target = target
        self.wordlist_1 = wordlist_path_1
        self.wordlist_2 = wordlist_path_2
        self.timeout = timeout

    def wordlist_data_extractor(self):
        data = []
        with open(self.wordlist_1, "r", encoding='utf-8') as f:
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

