# main.py
from .core_scanner.false_limit_detection import FalseDetector
import statistics
from fastapi import FastAPI
from .core_scanner.waf_scanner_module.waf_module_combined import WafDetectionModel
from .core_scanner.main_scanner import Scanner
import uvicorn
from .core_scanner.rate_limiting import RateLimitDetector
from .core_scanner.target_fingerprinting import WarmUpModel
from .models_for_main import Target
from .models_for_main import RateLimit
from .models_for_main import WafModel 
from .models_for_main import FalseDetectorModel

app = FastAPI(title="ReconSage V1.1.5")

@app.get("/")
def home():
    return {
        "Scanner name": "ReconSage V1.1.5",
        "Message": "Your scanner is working now lets start",
        "API Endpoints": {
            "scan": "/scan [POST]",
            "rate_limit": "/rate/limit [POST]",
            "waf_scan" : "/waf/scan [POST]",
            "false_detector" : "/false/positive [POST]" 
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

@app.post("/waf/scan")
async def waf_scan(waf_scan_model:WafModel):
    waf_detection_obj = WafDetectionModel(
        target=waf_scan_model.target,
        concurrency=waf_scan_model.concurrency, 
        timeout=waf_scan_model.timeout,
        lists_of_words=waf_scan_model.list_of_words
    )
    passive_scan_result = await waf_detection_obj.passive_main_scan()
    active_scan_result = await waf_detection_obj.main_active_scan_(
        headers=waf_scan_model.headers
    )
    return {
        "passive_scan_result" : passive_scan_result,
        "active_scan_result" : active_scan_result
    }
@app.post("/rate/limit")
async def scan_for_rate_limits(rate_limit: RateLimit):
    try:
        warmup_model = WarmUpModel()
        scan_result = await warmup_model.benign_request(
            target=rate_limit.target, 
            domains=rate_limit.domains, 
            concurrency=rate_limit.concurrency, 
            timeout=rate_limit.timeout
        )
        
        concurrency_rate = scan_result.get("calculated_concurrency", [])
        timeout_rate = scan_result.get("calculated_timeout", [])
        
        # Safe median with defaults
        concurrency = int(statistics.median(concurrency_rate)) if concurrency_rate else rate_limit.concurrency
        timeout = int(statistics.median(timeout_rate)) if timeout_rate else rate_limit.timeout
    
        rate_limit_scanner = RateLimitDetector(
            target=rate_limit.target,
            timeout=timeout,
            concurrency=concurrency,
            json_file_name=rate_limit.json_file_name,
            json_file_path=rate_limit.json_file_path,
            list_dirs=rate_limit.user_paths  # 50 requests - will trigger GitHub's 60/hour limit
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

@app.post("/false/positive")
async def scan(false_detector_model:FalseDetectorModel):
    warmup_model = WarmUpModel()
    benign_req = await warmup_model.benign_request(
        target=false_detector_model.target,
        concurrency=false_detector_model.concurrency,
        timeout=false_detector_model.timeout,
        domains=false_detector_model.list_of_targets
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
    false_detector_obj = FalseDetector(
        target=false_detector_model.target, 
        json_file_name=false_detector_model.json_file_name, 
        json_file_path=false_detector_model.json_full_path, 
        concurrency=concurrency, 
        timeout=timeout
    )
    scan_result = await false_detector_obj.execute_scan(
        json_file_to_read=false_detector_model.json_file_to_read
    )    
    
    return {
        "scan_result" : scan_result,
        "concurrency_rate" : concurrency_rate,
        "timeout_rate" : timeout_rate
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)