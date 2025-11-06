# ReconSage

![Version](https://img.shields.io/badge/version-1.1.5-blue)
![Python](https://img.shields.io/badge/python-3.11-green)
![Docker pulls](https://img.shields.io/badge/docker%20pulls-50+-orange)

A fast, opinionated asynchronous directory/subdomain enumerator and HTTP recon tool built with FastAPI + httpx. Designed for **authorized security testing**, ReconSage focuses on speed, simple JSON logs and post-scan false-positive heuristics.

---

## Legal & Ethical Notice

**Only run ReconSage against systems you own or have explicit, written permission to test.** Using this tool against third-party systems without authorization is illegal and unethical. The author and contributors are not responsible for misuse.

Include this in your engagement paperwork and follow your target's scope, rate limits, and disclosure rules.

---

## Features

* Asynchronous HTTP requests using `httpx.AsyncClient` with semaphore throttling
* Pluggable wordlist support (compatible with SecLists layout)
* JSON output logs stored under `~/reconsage_logs/<folder>/`
* The logs of output contains the logs of errors redirects and server errors from the target and also contains the False Positive output which target scan generated while scanning this are all stored under one path same as where other logs are stored too
* Basic false-positive analysis (content-length patterns)
* Container-friendly: run via Docker / docker-compose
* Minimal, audit-friendly codebase (single-file scanner core)

---

## Quickstart (Docker + Compose)

**Recommended**: use docker-compose to mount host wordlists and persist logs.

1. Set host environment variables (Linux / macOS):

```bash
export WORDLISTS=/usr/share/seclists   # path where you keep SecLists on host
export LOGS=$HOME/reconsage_logs       # where logs will be stored on host
```

2. Start the service:

```bash
docker compose up -d
```

3. Test the API (example):

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target":"http://target.com/",
    "wordlist":"/wordlists/Fuzzing/fuzz-Bo0oM-friendly.txt",
    "wordlist_2":"/wordlists/Fuzzing/fuzz-Bo0oM.txt",
    "json_file_path":"quicktest",
    "json_file_name":"scan.json"
  }'
```
---

## Run without Docker (local virtualenv)

1. Create and activate a virtualenv:

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the app:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

---

## API

### GET `/`
**Response (JSON)** 
```json
{
  "Scanner name":"ReconSage V1.0",
  "Message":"Your scanner is working now lets start",
  "API Endpoints":"/api/v1/scan POST",
  "Note":"this is one endpoint but lets be real we can make this even more powerful"
}

```
### POST `/api/v1/scan`

**Body (JSON)**

```json
{
  "target": "http://localhost:3000/",
  "wordlist": "/path/to/wordlist", 
  "wordlist_2": "/path/to/wordlist",
  "json_file_path": "folder_name_where_you_want_to_save_the_json_logs",
  "json_file_name": "file_name.json"
}
```

**Response**: JSON object with `summary`, `files` (absolute paths inside container), `false_positives` and `status`.

**Examples**: I have a Seclist and from that i have choosed to use the Fuzzing directory and here is how it should look in yours too 

```json
{
  "target": "http://localhost:3000/",
  "wordlist": "/wordlists/Fuzzing/fuzz-Bo0oM-friendly.txt", 
  "wordlist_2": "/wordlists/Fuzzing/fuzz-Bo0oM-friendly.txt",
  "json_file_path": "quicktest",
  "json_file_name": "scan.json"
}
```
---

## Configuration / Environment

* `WORDLISTS` (host) → mounted to `/wordlists` inside container (read-only)
* `LOGS` (host) → mounted to `/home/appuser/reconsage_logs` inside container

Tips:

* Ensure the mounted `LOGS` directory has write permissions for the container user.
* If your host path is different (Windows), set env vars before `docker compose up`.

---

## Where logs are written

Logs are written to the user's home inside the container at:

```
/home/appuser/reconsage_logs/<json_file_path>/<json_file_name>
```
When you mount `LOGS` on the host, they will land in your host folder (e.g. `./reconsage_logs/<json_file_path>/`).

```
/home/<USERNAME>/reconsage_logs/<json_file_path>/<json_file_name>
```
The logs containing this much of files :- 
```
client_errors_{timestamp}.json
redirects_{timestamp}.json
server_errors_{timestamp}.json
```
---

## Troubleshooting

* **No wordlists found**: ensure the host `WORDLISTS` directory contains the requested files and is mounted at `/wordlists`.
* **Logs missing on host**: ensure `LOGS` was mounted to `/home/appuser/reconsage_logs` and check permissions.
* **Permission denied writing logs**: adjust owner (e.g. `chown -R 1000:1000 $LOGS`) or give writable permissions.

---

## Responsible disclosure / safe defaults

* Default semaphore is set to 100 concurrent requests. Adjust in `main_scanner.py` to match target rules.
* Respect target rate limits and schedule scans in a way that won't disrupt services.
* Include a README section in any engagement packet that documents scan targets, windows, and safety checks.

---
## Contribution

1. Fork the repo
2. Create a feature branch
3. Open a PR which has meaningful features suggestion , bugs fixes in code 
4. Else your PR will be canceled from the section 
5. You can raise issue in the GitHub if you find any issues while using the scanner in its any part of it 

Please open issues for bugs or feature requests. Be explicit about test cases and include sample payloads where possible.

---

## LICENSE

MIT — see LICENSE file.

---

## Credits
* Coffee & Laptop with the Arch Linux 
* Built with `FastAPI`, `httpx` and `uvicorn`.
* Leveraging SecLists format (if you choose to include them) — [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

---