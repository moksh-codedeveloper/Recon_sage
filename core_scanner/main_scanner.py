# core_scanner/main_scanner.py
import datetime
import asyncio
import httpx

from core_scanner.target_fingerprinting import PassiveFingerprint
from .json_logger import JSONLogger


class Scanner:
    def __init__(self, target: str, wordlist_1: str, wordlist_2: str,
                 json_file_name: str, json_file_path: str, timeout, concurrency):

        if not target or not str(target).strip():
            raise ValueError("target URL is required")

        self.target = target.strip()
        self.timeout = timeout
        self.wordlist_1 = str(wordlist_1).strip() if wordlist_1 else None
        self.wordlist_2 = str(wordlist_2).strip() if wordlist_2 else None
        self.concurrency_rate = concurrency

        if not json_file_name or not str(json_file_name).strip():
            raise ValueError("json_file_name is required")

        self.json_file_name = str(json_file_name).strip()
        self.json_file_path = str(json_file_path).strip() if json_file_path else "default"

    async def run_scan(self):

        result = {}
        error_status_code = []
        redirect_status_code = []
        success_status_code = []
        server_status_code = []

        pf = PassiveFingerprint(
            target=self.target,
            timeout=self.timeout,
            concurrency=self.concurrency_rate
        )

        # Load wordlists
        wordlist_data_1 = pf.wordlist_data_extractor(self.wordlist_1)
        wordlist_data_2 = pf.wordlist_data_extractor(self.wordlist_2) if self.wordlist_2 else []

        all_domain = wordlist_data_1 + wordlist_data_2

        sem = asyncio.Semaphore(self.concurrency_rate)

        # ------------------------------
        # SHARED CLIENT — HUGE SPEED BOOST
        # ------------------------------
        async with httpx.AsyncClient(timeout=self.timeout) as client:

            async def bounded_scan(domain: str):
                async with sem:
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    scanned_output = await pf.scan_data(domain, client)
                    return timestamp, scanned_output

            tasks = [bounded_scan(domain) for domain in all_domain]
            all_results = await asyncio.gather(*tasks)

        # ------------------------------
        # Process collected results
        # ------------------------------
        for timestamp, scanned_result in all_results:

            url = scanned_result["url"]
            status_code = scanned_result.get("status_code", 0)
            body_text = scanned_result.get("response_body", "")
            hash_text = pf.hash_snippet(body_text)

            headers = dict(scanned_result.get("headers", {}))

            result[url] = {
                "status_code": status_code,
                "headers": headers,
                "hash_text": hash_text,
                "latency_ms": scanned_result.get("latency_ms"),
                "timestamps": timestamp,
                "content_length": scanned_result.get("content_length", 0),
                "error": scanned_result.get("error"),
            }

            # Categorize
            if 200 <= status_code < 300:
                success_status_code.append(url)
            elif 300 <= status_code < 400:
                redirect_status_code.append(url)
            elif 400 <= status_code < 500:
                error_status_code.append(url)
            else:
                server_status_code.append(url)

        # ------------------------------
        # Log output
        # ------------------------------
        success_logs = {
            "message": "The detailed logs to understand your victim more clearly",
            "result": result,
            "successfully_accessed_urls": success_status_code,
            "error_accessing_url": len(error_status_code),
            "redirect_access_url": len(redirect_status_code),
            "server_error_access_url": len(server_status_code),
        }

        logger = JSONLogger(
            json_file_name=self.json_file_name,
            json_file_path=self.json_file_path
        )
        logger.log_to_file(success_logs)

        return {
            "message": "Successfully done the scan results are all created!",
            "scanned_result": result,
            "more_detailed": {
                "length_of_successful_url": len(success_status_code),
                "length_of_error_url": len(error_status_code),
                "length_of_redirect_url": len(redirect_status_code),
                "length_of_server_error": len(server_status_code)
            },
            "status_code": 200
        }
