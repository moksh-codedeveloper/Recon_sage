# main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from core_scanner.main_scanner import Scanner
import uvicorn
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("reconsage_main")


class Target(BaseModel):
    target: str
    wordlist: str
    wordlist_2: str
    json_file_path: str
    json_file_name: str


app = FastAPI(title="ReconSage V1.1.5")


@app.get("/")
def home():
    return {
        "Scanner name": "ReconSage V1.0",
        "Message": "Your scanner is working now lets start",
        "API Endpoints": "/api/v1/scan POST",
        "Note": "this is one endpoint but lets be real we can make this even more powerful"
    }


@app.post("/api/v1/scan")
async def run_scan(target: Target):
    try:
        scanner = Scanner(
            target=target.target,
            wordlist_1=target.wordlist,
            wordlist_2=target.wordlist_2,
            json_file_path=target.json_file_path,
            json_file_name=target.json_file_name,
        )
    except ValueError as e:
        # bad input from client
        raise HTTPException(status_code=400, detail=str(e))

    try:
        result = await scanner.run_scan()
    except Exception as e:
        # unexpected internal error -> return a friendly JSON error
        logger.exception("Unhandled exception while running scan")
        raise HTTPException(status_code=500, detail="Internal server error during scan")

    # If scanner returns an error structure (your run_scan returns it), forward as 400
    if isinstance(result, dict) and result.get("status") and result["status"] != 200:
        # Keep structure, but send 400 so clients know it failed
        raise HTTPException(status_code=400, detail=result)

    return result


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
