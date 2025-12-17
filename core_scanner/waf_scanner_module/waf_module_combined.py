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
    
    def status_codes_analysis(self, all_status_code_list:list):
        direct_status_codes_occured_in_waf = []
        waf_status_code = [409, 405, 444, 429, 990, 900, 406, 401, 404, 403]
        for curr in all_status_code_list:
            if curr  in waf_status_code:
                direct_status_codes_occured_in_waf.append(curr)
        
        server_error_redirect_error_status_codes = []
        firewall_error_codes_other_codes = []
        for curr in all_status_code_list:
            if curr >= 500 and curr < 600:
                server_error_redirect_error_status_codes.append(curr)
            
            if curr >= 300  and curr < 400:
                server_error_redirect_error_status_codes.append(curr)
            
            if curr >= 900:
                firewall_error_codes_other_codes.append(curr)
        return {
            "message" : "Here are the findings from the scan  on your status codes list",
            "direct_status_code_analysis" : direct_status_codes_occured_in_waf,
            "server_error_redirect_codes" : server_error_redirect_error_status_codes,
            "firewall_error_and_other_codes" : firewall_error_codes_other_codes
        }