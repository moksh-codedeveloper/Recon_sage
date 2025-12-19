import httpx, asyncio 
import ssl
from ..json_logger import JSONLogger
import statistics

class WafModel:
    def __init__(self, target:str, timeout:int, concurrency:int, lists_of_words:list):
        self.target = target
        self.client = httpx.AsyncClient(timeout=timeout)
        self.sem = asyncio.Semaphore(concurrency)
        # Check to ensure the size does not exceeds the scanners original standardized size 
        if len(lists_of_words) >= 10:
            self.list_of_words = list_of_words[:10]
        self.list_of_words = lists_of_words

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
                "latencies_ms" :  resp.elapsed.total_seconds()  * 1000,
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

    def detection_using_lat(self, latencies_list:list):
        if len(latencies_list) < 2:
            return []
        
        mean = statistics.mean(latencies_list)
        std_dev = statistics.stdev(latencies_list)

        thresholds = mean + (2 * std_dev)

        return [x for x in latencies_list if x > thresholds]

    async def full_recon_scan(self):
        async with self.sem:
            tasks = [self.recon_info(domain) for domain in self.list_of_words]
            all_result = await asyncio.gather(*tasks)
        all_latencies = []
        all_status_code = []
        for results in all_result:
            if results["status_code"] != 0:
                all_status_code.append(results["status_code"])
            
            if results["latencies_ms"] != 0:
                all_latencies.append(results["latencies_ms"])
            
        return {
            "all_latencies" : all_latencies,
            "all_status_code" : all_status_code
        }

    async def main_scan(self):
        result_scan = await self.full_recon_scan()
        latencies_list = result_scan["all_latencies"]
        status_code_list = result_scan["all_status_code"]
        
        # Feeding the values to the detectors
        result_status_code_analysis = self.status_codes_analysis(status_code_list)
        result_latencies_analysis = self.detection_using_lat(latencies_list=latencies_list)

        # analysing the results from the 2 detectors
        direct_status_code_analysis = result_status_code_analysis["direct_status_code_analysis"]
        server_error_redirect_codes = result_status_code_analysis["server_error_redirect_codes"]
        firewall_error_and_other_codes = result_status_code_analysis["firewall_error_and_other_codes"]

        waf_score_based_status_code = 0
        waf_score_based_latencies = 0

        if len(direct_status_code_analysis) >= 1:
            waf_score_based_status_code += 10
        
        if len(server_error_redirect_codes) >= 1:
            waf_score_based_status_code += 20

        if len(firewall_error_and_other_codes) >= 1:
            waf_score_based_status_code += 50
        
        if  len(result_latencies_analysis) >= 1:
            waf_score_based_latencies += 60
        
        result = {
            "direct_waf_status_codes_detected" : direct_status_code_analysis,
            "server_error_redirect_codes" : server_error_redirect_codes,
            "firewall_error_and_other_codes" : firewall_error_and_other_codes
        }
        return{
            "message" : "Here is the detailed report on our analysis by our two of the OG detectors",
            "waf_score_based_on_status_codes" : waf_score_based_status_code,
            "waf_score_based_on_latencies" : waf_score_based_latencies,
            "all_metrices" : result
        }