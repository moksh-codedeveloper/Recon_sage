import httpx, asyncio 
import ssl
from ..json_logger import JSONLogger
class WafModel:
    def __init__(self, target:str, timeout:int, concurrency:int, lists_of_words:list):
        self.target = target
        self.client = httpx.AsyncClient(timeout=timeout)
        self.sem = asyncio.Semaphore(concurrency)
    async def __aclose__(self):
        await self.client.aclose()
     
    async def recon_info(self, domain):
        subtarget = self.target + domain
        tls_info = {}

        try:
            resp = await self.client.get(subtarget)

            if subtarget.startswith("https://"):
                stream = resp.extensions.get("network_stream")
                if stream:
                    ssl_object = stream.get_extra_info("ssl_object")
                    if ssl_object:
                        cipher_info = ssl_object.cipher()
                        tls_info = {
                            "tls_version": ssl_object.version(),
                            "cipher_info": cipher_info,
                            "cipher_suite": cipher_info[0] if cipher_info else None,
                            "cert": ssl_object.getpeercert()
                        }

            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "url": str(resp.url),
                "tls_info": tls_info
            }

        except Exception as e:
            print(f"There is exception here :- {e}")
            return {
                "status_code": 0,
                "headers": {},
                "url": "",
                "tls_info": {},
                "message": f"WAF module error :- {e}"
            }




async def main():
    print("======= Scan Report and summary here we go from here to there ======")
    target = "https://google.com/"
    wordlist = ["", "admin", "profile"]
    json_file_name = "research_data.json"
    json_file_path = "research_purpose_data"
    json_logger_obj = JSONLogger(json_file_name=json_file_name, json_file_path=json_file_path)
    log_for_scans = {}
    waf_model_obj = WafModel(target=target, lists_of_words=wordlist, concurrency=100, timeout=10)
    for domain in wordlist:
        scan_result = await waf_model_obj.recon_info(domain)
    
    for key, values in scan_result.items():
        log_for_scans[key] = values

    json_logger_obj.log_to_file(logs=log_for_scans)
    
    await waf_model_obj.__aclose__()

asyncio.run(main())