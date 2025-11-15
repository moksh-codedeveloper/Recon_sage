import httpx
class AIMDConcurrencyDataGather:
    def __init__(self,target_url, status_code, current_concurrency_limit, current_timeout_limit):
        self.target_url = target_url
        self.concurrency_limit = current_concurrency_limit
        self.timeout_limit = current_timeout_limit
        self.alpha = 1
        self.beta = 0.5
        self.status_code = status_code
        self.base_concurrency = 100
        self.max_concurrency = 200
    def data_to_dict(self):
        collected_data = {
            "target" : self.target_url,
            "current_concurrency_limit" : self.concurrency_limit,
            "current_timeout_limit" : self.timeout_limit,
            "status_code" : self.status_code
        }
        return collected_data
    
    def aimd_calculator(self):
        if 200 <= self.status_code < 300:
            self.concurrency_limit += self.alpha * 10
            self.timeout_limit = max(1, self.timeout_limit - 1)
        elif 400 <= self.status_code < 600 :
            self.concurrency_limit = int(self.concurrency_limit * self.beta)
            self.timeout_limit += 10
        
        if 429 == self.status_code:  # rate limit
            self.concurrency_limit = int(self.concurrency_limit * (self.beta ** 1.5))
            self.timeout_limit += 15
        warning = None
        error = None
        self.concurrency_limit = max(self.base_concurrency, min(self.concurrency_limit, self.max_concurrency))
        if 10 <= self.concurrency_limit < 30:
            warning = "Due to too much errors in the server you should consider stopping the scan because this website doesn't seem right"
        
        if self.concurrency_limit < 5:
            error = "I am stopping this scan because this server is either dead or it has too much security may be it is too much secure server"
        return {
            "target" : str(self.target_url),
            "status_code" : self.status_code,
            "new_concurrency" : self.concurrency_limit,
            "new_timeout" : self.timeout_limit,
            "error" : error ,
            "warning" : warning
        }