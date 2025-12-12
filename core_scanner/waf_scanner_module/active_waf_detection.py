import httpx 
import ssl

class ActiveWafScan:
    def __init__(self, timeout, concurrency, target:str, json_file_name:str, json_file_path:str, wordlist:list, headers:dict, params:str):
        self.target = target
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path
        if len(wordlist) <= 5:
            self.wordlist = wordlist
        else :
            self.wordlist = wordlist[:5]
        self.headers = headers
        self.params = params
        self.concurrency = concurrency
        self.timeout = timeout
        self.sem = asyncio.Semaphore(self.concurrency)

    async def probe_target(self, domain):
        try:
          async with httpx.AsyncClient(timeout=self.timeout) as client:
            sub_target = self.target + domain
            resp = await client.get(sub_target, headers=self.headers, params=self.params)
            return {
                "url" : str(resp.url), 
                "headers" : dict(resp.headers),
                "status_code" : resp.status_code,
                "latency_ms" : resp.elapsed.total_seconds(),
                "timestamps" : datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            }
        except Exception as e:
            print(f"[-]Exceptions occured here :- {e}")
            return {
                "url" : "",
                "headers" : {},
                "status_code" : 0,
                "latency_ms" : 0,
                "timestamps" : datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
                "message" : f"There is some error which has occured here suggestion solve this and restart the scanning :- {e}"
            }
    async def  harmless_request(self, domain):
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                sub_target = self.target + domain
                resp = await client.get(sub_target)
                stream = resp.extensions.get("network_stream")
                if not stream:
                    return {}
                ssl_object = stream.get_extra_info("ssl_object")
                if not isinstance(ssl_object, (ssl.SSLSocket, ssl.SSLObject)):
                    return {}
                return {
                    "message" : "This scan batch got successful",
                    "status_code" : resp.status_code,
                    "url" : str(resp.url),
                    "headers" : dict(resp.headers),
                    "tls_version" : ssl_object.version(),
                    "tls_cipher" : ssl_object.cipher(),
                    "tls_cert" : ssl_object.getpeercert(),
                    "latency_ms" : resp.elapsed.total_seconds(),
                    "timestamps" :  datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                }
        except Exception as e:
            print(f"DEBUG there is scan exception in the harmless request in here :- {e}")
            return {
                "message" : f"There is exception here in the harmless request method :- {e}",
                "url" : "",
                "headers" : {},
                "status_code" : 0,
                "latency_ms" : 0,
                "timestamps" : datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
                "tls_version" : None,
                "tls_cipher": None,
                "tls_cert" : None
            }
    async def check_for_waf_status_code(self):
        target_result = {}
        status_code_for_waf = [406, 419, 420,  429, 444, 450, 494, 499, 510, 521, 522, 523, 525, 526, 530]
        try:
            urls_with_status_code_detected_waf = {}
            all_urls_has_the_status_code = []
            async with self.sem:
                tasks = [self.probe_target(domain) for domain in self.wordlist]
                all_result = await asyncio.gather(*tasks)
                for result in all_result:
                    if result["status_code"] in status_code_for_waf:
                        target_result[result["url"]] = {
                            "status_code" : result["status_code"],
                            "headers" : result["headers"],
                            "latency_info" : result["latency_ms"],
                            "timestamps" : result["timestamps"]
                        }
                        urls_with_status_code_detected_waf[result["url"]] = result["status_code"]
                        all_urls_has_the_status_code.append(result["url"])

            logger_obj = JSONLogger(json_file_name=self.json_file_name, json_file_path=self.json_file_path)
            logs_for_json_file = {
                "message" : "This is the file report with the detailed data",
                "target_result" : target_result,
            }
            logger_obj.log_to_file(logs_for_json_file)
            return {
                "message" : "This is generated summary from the data came from the server",
                "target_result" : len(target_result),
                "length_of_urls_list_has_the_waf_status_code" : len(all_urls_has_the_status_code),
                "more_detailed_data" : urls_with_status_code_detected_waf
            }
        except Exception as e:
          print(f'There is exception in the run_scan in the method of the active waf :- {e}')
          return {
            "message" : "This is the exception from check method used for the status code detection for waf and cdns and all that",
            "target_result" : 0,
            "length_of_urls_list_has_the_waf_status_code" : 0,
            "more_detailed_data" : {}
          }