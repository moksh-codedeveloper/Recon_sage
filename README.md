# ReconSage

![Version](https://img.shields.io/badge/version-1.9-blue)
![Python](https://img.shields.io/badge/python-3.11-green)
![Docker pulls](https://img.shields.io/badge/docker%20pulls-85+-orange)

ReconSage is an asynchronous reconnaissance framework focused on **signal quality** rather than raw speed.  
It combines subdirectory discovery with WAF awareness, rate-limit detection, and false-positive reduction into a single, feedback-driven workflow.

---

## What is ReconSage?

ReconSage is **not just a directory brute-forcer**.

It is a backend-first reconnaissance system designed to observe **how a server behaves under controlled pressure**, then reuse those observations to reduce noise in later scans.

Most tools treat:
- directory scanning  
- WAF detection  
- rate limiting  
- false positives  

as separate problems.

ReconSage treats them as **dependent signals**.

---

## Core Design Philosophy

ReconSage is built on three principles:

### 1. Signal > Volume
Sending more requests does not guarantee better results.  
ReconSage prioritizes **response behavior**, not request count.

### 2. Feedback-Driven Scanning
Outputs from one phase (status codes, headers, body hashes, timing) are reused as **inputs** for later phases.

Logs are not dead artifacts — they are part of the scanning pipeline.

### 3. Explicit Risk Ownership
ReconSage does not attempt to hide its activity by default.
If a defense is triggered, that behavior is considered **valuable information**, not failure.

---

## Current Features (v1.9.1)

### Subdirectory Scanner
- Fully async, HTTPX-based
- Adaptive concurrency using AIMD
- Supports dual wordlists
- Designed to surface behavioral anomalies, not just `200 OK`

### WAF Detector Module
- This module has power of both active and passive scanner
- This module detects the WAF using the signals
- This module works even if the server changes the data responses or anything because behavior can't be changed its felt

### Rate-Limit Detection
- Identifies soft and hard limits
- Detects the real life WAF from any target
- Updated and added more strict and more ways of detection in the Rate Limit detection 
- Removed the headers way of rate limit detection added the signals  based and behavior based detection

### False-Positive Detection
- Hash-based response comparison
- Uses scanner output as input
- Designed to eliminate “fake 200s” and wildcard responses

### Structured JSON Logging
- All modules emit structured logs
- Logs are reusable across modules
- Path handling is resilient by design

---

#### Note :- In every module i have integrated the AIMD module it calculates the concurrency and timeout which is like managing speed and warm up scans before the real scans begin 
---

## What ReconSage Does NOT Do

ReconSage is **not**:
- an exploit framework  
- a vulnerability scanner  
- a WAF bypass tool  
- a stealth-by-default scanner  

It is a **reconnaissance and observation tool**.

If you want exploitation or automation, this is intentionally not that.

---

## Architecture

ReconSage currently operates in **backend mode**, exposing functionality through HTTP endpoints.

Planned architecture:
1. Backend mode (stable)
2. CLI mode (interactive, user-driven decisions)

The CLI will act as an intelligent control layer over the backend.

---

## Available Endpoints

1. `/scan`  
   Main subdirectory scanner

2. `/rate/limit`  
   Rate-limit detection module

3. `/waf/scan`  
   WAF detection (passive, active both ready)

4. `/false/positive`  
   False-positive detection module

---

## Sample Requests

`/scan POST`
```json
{
  "target": "http://testphp.vulnweb.com/",
  "wordlist": "/usr/share/seclists/Fuzzing/fuzz-Bo0oM-friendly.txt",
  "wordlist_2": "/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt",
  "json_file_name": "recon_sage_logs.json",
  "json_file_path": "ReconSage_logs",
  "concurrency": 100,
  "timeout": 10
}
```

---

`/rate/limit POST`

```json
{
  "target": "https://api.github.com/",
  "json_file_name": "rate_limit.json",
  "json_file_path": "rate_limit_logs",
  "domains": [],
  "user_paths": [], // Should be of length 10 or more than 10
  "concurrency": 5,
  "timeout": 10
}
```

---

`/waf/scan POST`

```json
{
    "target" : "http://testphp.vulnweb.com/",
    "list_of_words" : [],
    "json_file_name" : "waf_scan_test.json",
    "json_file_path" : "Waf_Scan_Result",
    "concurrency" : 100,
    "timeout" : 10,
    "headers" : {
        "user-agent" : "ReconSage V1.1",
        "server" : "ReconSage"
    }
}
```

---

`/false/positive POST`

```json
{
  "target": "http://testphp.vulnweb.com/",
  "json_file_name": "false_positive.json",
  "json_full_path": "False_Detector",
  "timeout": 10,
  "concurrency": 100,
  "json_file_to_read": "/home/<user>/ReconSage_logs/recon_sage_logs.json",
  "list_of_targets": ["", "favicon.ico", ".git/", "logs/"]
}
```

---

## Important Notes

* Some parameters (domains, wordlists, paths) are used by internal warm-up logic to calculate safe concurrency and timeout values.
* Rate-limit detection separates:
  * domains is a list used for AIMD calibration
  * user_paths is a list used for actual detection
  * user_paths is a list and should be of length at least 10 or more than 10 
* False-positive detection **must** consume logs generated by the main scanner.

Passing arbitrary JSON files will fail by design.

---

## Active WAF Detection (Status)

Active WAF detection exists only in the WAF module and is **still under development**.

It intentionally triggers defensive behavior to observe:

* status code anomalies
* response timing changes
* TLS and connection behavior (NOTE :- This is part of response is only for hackers to decide is this WAF protected or not)

### Use responsibly.

---

## Intended Audience

ReconSage is built for:

* infrastructure researchers
* advanced bug bounty hunters
* people who care about false positives
* users comfortable with async tooling and responsibility

If you are looking for plug-and-play exploitation, this is not the right tool.

---

## Ethics & Responsibility

ReconSage exposes behavior — it does not justify misuse.

You control:

* concurrency
* targets
* intensity

You own the consequences.

---

## Credits

* Coffee
* A laptop
* Unlimited curiosity

---

## Final Note

> “Good reconnaissance is not about speed.
> It’s about understanding how a system reacts.”

