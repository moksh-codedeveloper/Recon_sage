# main.py
import statistics
from fastapi import FastAPI
from pydantic import BaseModel
from core_scanner.main_scanner import Scanner
import uvicorn
import logging

from core_scanner.target_fingerprinting import WarmUpModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("reconsage_main")


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
    scan_model = Scanner(target=target.target, wordlist_1=target.wordlist, wordlist_2=target.wordlist_2, json_file_name=target.json_file_name, json_file_path=target.json_file_path, concurrency=concurrency, timeout=timeout)
    main_scan_result = await scan_model.run_scan()
    return main_scan_result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
