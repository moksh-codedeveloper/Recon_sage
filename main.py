from fastapi import FastAPI
from pydantic import BaseModel
from core_scanner.main_scanner import Scanner
# from datetime import datetime
import uvicorn
# Fix this class!
class Target(BaseModel):  # ← Need to inherit from BaseModel!
    target: str
    wordlist: str
    wordlist_2: str
    json_file_path:str
    json_file_name:str


app = FastAPI()

@app.get("/")
def home():
    return {
        "Scanner name": "ReconSage V1.0",
        "Message": "Your scanner is working now lets start",
        "API Endpoints": "/scan POST",
        "Note": "this is one endpoint but lets be real we can make this even more powerful"
    }

@app.post("/api/v1/scan")
async def run_scan(target:Target):
    scanner = Scanner(target=target.target, wordlist_1=target.wordlist, wordlist_2=target.wordlist_2, json_file_path=target.json_file_path, json_file_name=target.json_file_name)
    result = await scanner.run_scan()
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)