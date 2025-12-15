import httpx, asyncio
from core_scanner.json_logger import JSONLogger 
import ssl
class WafModel:
    def __init__(self, target:str, json_file_name:str, json_file_path:str, timeout:int, concurrency:int, lists_of_words:list):
        self.target = target
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
        self.client = httpx.AsyncClient(timeout=timeout)
        self.sem = asyncio.Semaphore(concurrency)
    
    async def recon_info(self, domain):
        subtarget = domain + self.target
        try:
            resp =  await self.client.get(subtarget)
            if self.target.startswith("https://"):
                stream = resp.extensions.get("network_stream")
                if not stream :
                    return {}
                tls_info = {} 
                ssl_object = stream.get_extra_info("ssl_object")
                tls_version = ssl_object.version()
                cipher_info = ssl_object.cipher()
                cipher_suite = ssl_object.cipher_info[0] if cipher_info else None
                cert = ssl_object.getpeercert()
                tls_info = {
                    "tls_version" : tls_version,
                    "cipher_info" : cipher_info,
                    "cipher_suite" : cipher_suite,
                    "cert" : cert
                }
            return {
                "status_code" : resp.status_code,
                "headers" : dict(resp.headers),
                "url" : str(resp.url),
                "tls_info" : tls_info
            }
        except Exception as  e:
            print(f"There is exception here  :- {e}")
            return {
                "status_code" : 0,
                "headers" : {},
                "url" : "",
                "tls_info" : {},
                "message" :  f"There is  one error which has occur please solve that  i am talking from the waf module over and out :- {e}"
            }