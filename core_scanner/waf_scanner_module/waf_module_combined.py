import httpx, asyncio 
import ssl
from core_scanner.json_logger import JSONLogger
import statistics

class WafDetectionModel:
    def __init__(self, target:str, timeout:int, concurrency:int, lists_of_words:list):
        self.target = target
        self.client = httpx.AsyncClient(timeout=timeout)
        self.sem = asyncio.Semaphore(concurrency)
        # Check to ensure the size does not exceeds the scanners original standardized size 
        if len(lists_of_words) > 10:
            self.list_of_words = lists_of_words[:10]
        else:
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

    async def passive_main_scan(self):
        async with self.sem :
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

    async def active_probing(self, headers:dict, urls:str):
        try:
            resp = await self.client.get(urls)
            return {
                "status_code"  : int(resp.status_code),
                "url" : str(resp.url),
                "headers" : dict(resp.headers),
                "latency_ms" : resp.elapsed.total_seconds() * 1000,
            }
        except Exception as e:
            print(f"There is exception in the scan and here it is :- {e}")
            return {
                "status_code" : 0,
                "urls" : "",
                "message" : f"I think there  is somem  errors you should solve it here it  is :- {e}",
                "headers" : {},
                "latency_ms" : 0,
            }

    async def active_scan(self, headers:dict):
        all_urls = []
        all_status_code = []
        all_latencies_list = []
        try:
            for domains in self.list_of_words:
                full_urls = self.target + domains
                all_urls.append(full_urls)
            tasks = [self.active_probing(urls=urls, headers=headers) for urls in all_urls]
            all_result = await asyncio.gather(*tasks)
            all_headers_list = []
            for result in all_result:
                all_status_code.append(result["status_code"])
                all_latencies_list.append(result["latency_ms"])
                all_headers_list.append(result["headers"])
            return {
                "message" : "This is the comprehensive list of result which i got from the target and looks like you  can handle it can't you ?? :)",
                "all_status_codes_list" : all_status_code,
                "all_latencies_list": all_latencies_list,
                "all_headers"  : all_headers_list
            }
        except Exception as e:
            print("This is the error which is trying to stop you from the full  fledged result of the scan ", e)
            return {
                "message" : f"Something went wrong please check the error and exception if they have occur and try to solve them :- {e}",
                "all_status_codes_list" : [],
                "all_latencies_list" : [],
                "all_headers": []
            }
    
    def latency_trend_checker(self, all_latency_ms:list):
        is_it_increasing_trend = False
        is_it_decreasing_trend = False

        for i in range(1, len(all_latency_ms)):
            curr = all_latency_ms[i]
            prev = all_latency_ms[i-1]

            if curr > prev:
                is_it_increasing_trend = True
            
            if curr < prev: 
                is_it_decreasing_trend = True
        
        return {
            "is_it_decreasing_trend" : is_it_decreasing_trend,
            "is_it_increasing_trend" : is_it_increasing_trend
        }
    
    async def main_active_scan_(self, headers:dict):
        try:
            async with self.sem:
                scan_result = await self.active_scan(headers=headers)
            # Calculation for the latency and detection using the spikes and trend check on the latency list 
            latency_list = scan_result["all_latencies_list"]
            latency_spike_detection = self.detection_using_lat(latencies_list=latency_list)
            latency_trend_analies = self.latency_trend_checker(latency_list)
            
            # detection for the waf based and other status codes 
            status_code_list = scan_result["all_status_codes_list"]
            status_code_list_analysis = self.status_codes_analysis(all_status_code_list=status_code_list)
            waf_score_status_code = 0

            direct_status_code_analysis = status_code_list_analysis["direct_status_code_analysis"]
            server_error_redirect_codes = status_code_list_analysis["server_error_redirect_codes"]
            firewall_error_and_other_codes = status_code_list_analysis["firewall_error_and_other_codes"]

            waf_score_based_status_code = 0
            waf_score_based_latencies = 0

            if len(direct_status_code_analysis) >= 1:
                waf_score_based_status_code += 10
        
            if len(server_error_redirect_codes) >= 1:
                waf_score_based_status_code += 20

            if len(firewall_error_and_other_codes) >= 1:
                waf_score_based_status_code += 50

            if latency_spike_detection != []:
                if len(latency_spike_detection) >= 1:
                    waf_score_based_latencies += 20
            
            if latency_trend_analies["is_it_increasing_trend"] == True:
                waf_score_based_latencies += 80
            return {
                "message" : "Here is the massive results list of data from the server :- :0",
                "latency_related_data" : {
                    "latency_spike_detection" : latency_spike_detection,
                    "latency_trend_checks" : latency_trend_analies
                },
                "status_code_related_data" : {
                    "direct_waf_status_code" : direct_status_code_analysis,
                    "server_error_redirect_codes" : server_error_redirect_codes,
                    "firewall_error_and_other_codes" : firewall_error_and_other_codes
                },
                "waf_scores" : {
                    "waf_score_based_status_code" : waf_score_based_status_code,
                    "waf_score_based_latencies" : waf_score_based_latencies
                },
                "all_headers" : scan_result["all_headers"]
            }
        except Exception as e:
            print(f"there is an exception in the scan here :- {e}")
            return {
                "message" : f"There is exception here and here is the message :- {e}",
                "latency_related_data" : {},
                "status_code_related_data" : {},
                "waf_scores" : {},
                "all_headers" : {}
            }