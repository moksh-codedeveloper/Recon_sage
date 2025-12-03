# main.py

import statistics
from fastapi import FastAPI
from pydantic import BaseModel
from core_scanner.main_scanner import Scanner
import uvicorn
from core_scanner.rate_limiting import RateLimitDetector
from core_scanner.target_fingerprinting import WarmUpModel
from waf_scanner_module.waf_detection import WafDetection

class Target(BaseModel):
    target: str
    wordlist: str
    wordlist_2: str
    json_file_path: str
    json_file_name: str
    concurrency: int
    timeout: int

class RateLimit(BaseModel):
    target: str
    timeout: int
    concurrency: int
    json_file_name: str
    json_file_path: str

app = FastAPI(title="ReconSage V1.1.5")

@app.get("/")
def home():
    return {
        "Scanner name": "ReconSage V1.1.5",
        "Message": "Your scanner is working now lets start",
        "API Endpoints": {
            "scan": "/scan [POST]",
            "rate_limit": "/rate/limit [POST]"
        },
        "Note": "Built by 18yo hacker from India 🇮🇳🔥"
    }

@app.post("/scan")
async def main_scan(target: Target):
    try:
        warmup_scanner = WarmUpModel()
        scan_result = await warmup_scanner.benign_request(
            target=target.target, 
            domains=["/secret.txt", "/favicon.ico", "/secrets/secret.txt"], 
            concurrency=target.concurrency, 
            timeout=target.timeout
        )
        
        concurrency_rate = scan_result.get("calculated_concurrency", [])
        timeout_rate = scan_result.get("calculated_timeout", [])
        
        # Safe median with defaults
        concurrency = int(statistics.median(concurrency_rate)) if concurrency_rate else target.concurrency
        timeout = int(statistics.median(timeout_rate)) if timeout_rate else target.timeout
        
        scan_model = Scanner(
            target=target.target, 
            json_file_name=target.json_file_name, 
            json_file_path=target.json_file_path
        )
        main_scan_result = await scan_model.run_scan(
            wordlist_1=target.wordlist, 
            wordlist_2=target.wordlist_2, 
            concurrency=concurrency, 
            timeout=timeout
        )
        
        return {
            "main_scan_result": main_scan_result,
            "concurrency": concurrency,
            "timeout": timeout
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "message": "Main scan failed",
            "success": False
        }

@app.post("/rate/limit")
async def scan_for_rate_limits(rate_limit: RateLimit):
    try:
        warmup_model = WarmUpModel()
        scan_result = await warmup_model.benign_request(
            target=rate_limit.target, 
            domains=["/users/github", "/users/torvalds", "/users/python"], 
            concurrency=rate_limit.concurrency, 
            timeout=rate_limit.timeout
        )
        
        concurrency_rate = scan_result.get("calculated_concurrency", [])
        timeout_rate = scan_result.get("calculated_timeout", [])
        
        # Safe median with defaults
        concurrency = int(statistics.median(concurrency_rate)) if concurrency_rate else rate_limit.concurrency
        timeout = int(statistics.median(timeout_rate)) if timeout_rate else rate_limit.timeout
        
        # Generate 50 GitHub user endpoints to test rate limiting
        github_users = [
            "torvalds", "gvanrossum", "github", "microsoft", "google",
            "facebook", "nodejs", "rust-lang", "python", "tensorflow",
            "apple", "amazon", "netflix", "spotify", "adobe",
            "uber", "airbnb", "twitter", "meta", "oracle",
            "ibm", "intel", "amd", "nvidia", "samsung",
            "sony", "linux", "debian", "ubuntu", "fedora",
            "redhat", "centos", "arch", "gentoo", "slack",
            "discord", "zoom", "dropbox", "docker", "kubernetes",
            "ansible", "terraform", "jenkins", "gitlab", "bitbucket",
            "npm", "yarn", "webpack", "babel", "eslint"
        ]
        
        user_paths = [f"/users/{user}" for user in github_users]
        
        rate_limit_scanner = RateLimitDetector(
            target=rate_limit.target,
            timeout=timeout,
            concurrency=concurrency,
            json_file_name=rate_limit.json_file_name,
            json_file_path=rate_limit.json_file_path,
            list_dirs=user_paths  # 50 requests - will trigger GitHub's 60/hour limit
        )
        
        batch_result = await rate_limit_scanner.scan_batch()
        detect_rate_limit_result = rate_limit_scanner.detect_rate_limited(batch=batch_result)
        
        return detect_rate_limit_result
    
    except Exception as e:
        return {
            "error": str(e),
            "message": "Rate limit scan failed",
            "success": False
        }

class WafModel(BaseModel):
    target:str
    wordlist:list
    json_file_name:str
    json_file_path:str
    concurrency:int
    timeout:int
    
@app.post("/waf/scan")
async def waf_scan(waf_model:WafModel):
    warm_up = WarmUpModel()
    benign_req = await warm_up.benign_request(
        waf_model.target, 
        waf_model.wordlist, 
        waf_model.concurrency, 
        waf_model.timeout
    )
   
    concurrency_rate = benign_req["calculated_concurrency"]
    timeout_rate = benign_req["calculated_timeout"]

    # Safe defaults
    concurrency = 100
    timeout = 10

    # Only calculate median if lists are not empty
    if concurrency_rate and len(concurrency_rate) > 0:
        concurrency = statistics.median(concurrency_rate)
    
    if timeout_rate and len(timeout_rate) > 0:
        timeout = statistics.median(timeout_rate)

    waf_detection_obj = WafDetection(
        target=waf_model.target, 
        wordlist=waf_model.wordlist, 
        json_file_name=waf_model.json_file_name, 
        json_file_path=waf_model.json_file_path , 
        concurrency=concurrency, 
        timeout=timeout
    )

    scan_result = await waf_detection_obj.run_scan()
    return scan_result

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)