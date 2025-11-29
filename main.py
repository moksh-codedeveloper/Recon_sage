# main.py
import statistics
from fastapi import FastAPI
from pydantic import BaseModel
from core_scanner.main_scanner import Scanner
import uvicorn
from core_scanner.rate_limiting import RateLimitDetector
from core_scanner.target_fingerprinting import WarmUpModel

class Target(BaseModel):
    target: str
    wordlist: str
    wordlist_2: str
    json_file_path: str
    json_file_name: str
    concurrency: int
    timeout: int


app = FastAPI(title="ReconSage V1.1.5")


@app.get("/")
def home():
    return {
        "Scanner name": "ReconSage V1.0",
        "Message": "Your scanner is working now lets start",
        "API Endpoints": "/api/v1/scan POST",
        "Note": "this is one endpoint but lets be real we can make this even more powerful"
    }

@app.post("/scan")
async def main_scan(target:Target):
    warmup_scanner = WarmUpModel()
    scan_result = await warmup_scanner.benign_request(target=target.target, domains=["/secret.txt", "/favicon.ico", "/secrets/secret.txt"], concurrency=target.concurrency, timeout=target.timeout)
    concurrency_rate = scan_result["calculated_concurrency"]
    timeout_rate = scan_result["calculated_timeout"]
    concurrency = int(statistics.median(concurrency_rate))
    timeout = int(statistics.median(timeout_rate))
    scan_model = Scanner(target=target.target, json_file_name=target.json_file_name, json_file_path=target.json_file_path)
    main_scan_result = await scan_model.run_scan(wordlist_1=target.wordlist, wordlist_2=target.wordlist_2, concurrency=concurrency, timeout=timeout)
    return {
        "main_scan_result" : main_scan_result,
        "concurrency" : concurrency,
        "timeout" : timeout
    }

class RateLimit(BaseModel):
    target: str
    timeout:int
    concurrency:int
    json_file_name: str
    json_file_path:str

@app.post("/rate/limit")
async def scan_for_rate_limits(rate_limit:RateLimit):
    warmup_model = WarmUpModel()
    scan_result = await warmup_model.benign_request(target=rate_limit.target, domains=["", "secrets.txt", "login.php", "/favicon.ico"], concurrency=rate_limit.concurrency, timeout=rate_limit.timeout)
    concurrency_rate = scan_result["calculated_concurrency"]
    timeout_rate = scan_result["calculated_timeout"]
    concurrency = int(statistics.median(concurrency_rate))
    timeout = int(statistics.median(timeout_rate))
    rate_limit_scanner = RateLimitDetector(
        target=rate_limit.target,
        timeout=timeout,
        concurrency=concurrency,
        json_file_name=rate_limit.json_file_name,
        json_file_path=rate_limit.json_file_path,
        list_dirs=["", "secrets.txt", "login.php", "/favicon.ico", "secrets/secrets.txt"]
    )
    batch_result = await rate_limit_scanner.scan_batch()
    detect_rate_limit_result = rate_limit_scanner.detect_rate_limited(batch=batch_result)
    return detect_rate_limit_result



if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
