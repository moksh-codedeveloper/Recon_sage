# Recon_sage 🔍⚡

Fast async directory enumeration tool for bug bounty hunters and penetration testers.

![Version](https://img.shields.io/badge/version-v1.1.3-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen)

---

## Overview

Recon_sage is an async directory enumeration scanner built with **FastAPI + httpx**.
It’s designed to be fast, configurable, and Docker-friendly. The repo now standardizes where logs and wordlists live inside the container and exposes safe environment variables so the tool behaves consistently on Linux, Windows and macOS.

---

## Key changes (v1.1.3)

* `JSONLogger` now respects `LOG_DIR` and falls back safely if not writable.
* Container runs as **non-root** and writes logs to `/app/result_log` by default.
* `main_scanner` resolves wordlists via optional `WORDLIST_DIR`.
* `docker-compose` examples for Linux and Windows included.
* API now returns absolute container log paths (which map to host mounts).
* Removed generated logs from repo and added `.gitignore` guidance.

---

## Quick concepts

* **Container-internal paths:** `/app/result_log` (logs) and `/usr/share/seclists` (wordlists).
* **Host mapping:** you mount host folders into these container paths; container writes to `/app/result_log` and those files persist on host.
* **Networking:**

  * On **Linux** you can use `--network host` (container sees host `localhost`).
  * On **Windows/macOS** use bridge networking and `host.docker.internal` as the target host address.

---

## Environment variables

* `LOG_DIR` — (preferred) absolute path inside container where logs are written (default: `/app/result_log` in image).
* `WORDLIST_DIR` — optional base path inside container for resolving relative wordlist names (e.g. `/usr/share/seclists`).
* `DEFAULT_TARGET` — optional default target used by your app if you choose to use it.
* `RECONSAGE_ALLOW_ABSOLUTE=1` — optional; allows JSONLogger to respect absolute `json_file_path` from caller (use carefully).

---

## Install & Run

### 1) Build (if you build locally)

```bash
# from repo root
docker build -t mokshmalde/reconsage:local .
```

### 2) Run — pick one (Linux or cross-platform)

#### Linux (recommended for local testing; allows using `http://localhost:3000` as target)

```bash
mkdir -p ~/reconsage_logs
docker run --rm -it --network host \
  -v /usr/share/seclists:/usr/share/seclists:ro \
  -v ~/reconsage_logs:/app/result_log \
  -e LOG_DIR=/app/result_log \
  mokshmalde/reconsage:local
```

* **Note:** when using `--network host` you should *not* use `-p` (it's ignored). Use `http://localhost:3000/` as scan `target`.

#### Cross-platform (Windows / macOS / Linux bridge)

```bash
mkdir -p ~/reconsage_logs
docker run --rm -it -p 8000:8000 \
  -v /usr/share/seclists:/usr/share/seclists:ro \
  -v ~/reconsage_logs:/app/result_log \
  -e LOG_DIR=/app/result_log \
  mokshmalde/reconsage:local
```

* Use `http://host.docker.internal:3000/` as `target` when calling the scan endpoint from inside container run with bridge networking (Windows or Docker Desktop).

---

## docker-compose (Linux/macOS)

`docker-compose.yml` (for most Linux/macOS use):

```yaml
version: "3.9"
services:
  reconsage:
    image: mokshmalde/reconsage:v1.1.3
    container_name: reconsage
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      LOG_DIR: /app/result_log
      WORDLIST_DIR: /usr/share/seclists
      DEFAULT_TARGET: http://host.docker.internal:3000/
    volumes:
      - ./reconsage_logs:/app/result_log
      - /usr/share/seclists:/usr/share/seclists:ro
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

Run:

```bash
docker compose up -d
```

---

## docker-compose.windows.yml (Windows)

`docker-compose.windows.yml`:

```yaml
version: "3.9"
services:
  reconsage:
    image: mokshmalde/reconsage:v1.1.3
    container_name: reconsage
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      LOG_DIR: /app/result_log
      WORDLIST_DIR: /usr/share/seclists
      DEFAULT_TARGET: http://host.docker.internal:3000/
    volumes:
      - ${WINDOWS_LOGS_PATH}:/app/result_log
      - ${WINDOWS_WORDLISTS_PATH}:/usr/share/seclists:ro
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

`.env.windows` (example — place next to compose file):

```
WINDOWS_LOGS_PATH=C:\Users\YourUser\reconsage_logs
WINDOWS_WORDLISTS_PATH=C:\Users\YourUser\wordlists
```

Run:

```powershell
docker compose -f docker-compose.windows.yml --env-file .env.windows up -d
```

---

## API quick usage

**Endpoint:** `POST /api/v1/scan`
**Headers:** `Content-Type: application/json`

Example body (use `host.docker.internal` on Windows/bridge, or `localhost` with `--network host`):

```json
{
  "target": "http://host.docker.internal:3000/",
  "wordlist_1": "Fuzzing/fuzz-Bo0oM-friendly.txt",
  "wordlist_2": "Fuzzing/fuzz-Bo0oM.txt",
  "json_file_path": "app_test_logs",
  "json_file_name": "app_real_target.json"
}
```

* If `WORDLIST_DIR` is set (e.g. `/usr/share/seclists`), you can pass relative names like `Fuzzing/...` and `main_scanner` will resolve them.

**Response:** includes `files.success_log` etc. — paths inside the container (e.g. `/app/result_log/app_real_target.json`) which map to your mounted host folder.

---

## Post-run checks & common problems

* **No such wordlist** → make sure host's wordlist folder is mounted into container path you expect (`/usr/share/seclists`).
* **All requests are exceptions (successful: 0)** → container cannot reach target. If using bridge network, switch to `host.docker.internal` (Windows/macOS) or use `--network host` on Linux.
* **Logs still in /root/** → ensure container is started with `LOG_DIR=/app/result_log` and that the image uses non-root user (Dockerfile provided).
* **Files accidentally committed to git** → remove them and add to `.gitignore` (commands below).

### Remove committed logs from git (do this now if you committed logs)

```bash
git rm -r --cached app_test_logs || true
echo "app_test_logs/" >> .gitignore
echo "reconsage_logs/" >> .gitignore
git add .gitignore
git commit -m "chore: remove generated logs and ignore log folders"
git push origin main
```

If you need to purge them from history, use `git filter-branch` or `git filter-repo` (I can provide commands).

---

## Build & push (Docker Hub)

Tag and push:

```bash
# build locally
docker build -t mokshmalde/reconsage:local .

# tag for release
docker tag mokshmalde/reconsage:local mokshmalde/reconsage:v1.1.3

# login & push
docker login -u <your-docker-username>
docker push mokshmalde/reconsage:v1.1.3

# optional: push latest
docker tag mokshmalde/reconsage:v1.1.3 mokshmalde/reconsage:latest
docker push mokshmalde/reconsage:latest
```

---

## Security & production notes

* **Rate limit & auth:** add API key or JWT to `/scan` for public deployment. Consider `slowapi` or a reverse-proxy to enforce rate limits.
* **Non-root in container:** Dockerfile sets a non-root user — keep that. If you mount a host dir, ensure appropriate permissions or use an entrypoint to `chown` mounted dir at start (careful with security).
* **Avoid `--network host` in multi-tenant or cloud environments.** Bridge network + `host.docker.internal` is safer and portable.
* **Legal:** only scan targets you are authorized to test.

---

## Roadmap

* Wildcard detection improvements
* DNS validation & MX checks
* Web UI dashboard + streaming results
* Multi-target / queueing with Redis/Celery or RQ
* Export to CSV/HTML and report generation
* Windows-friendly Docker image tests & CI

---

## Contributing

1. Fork
2. Create feature branch
3. Add tests where appropriate (esp. path resolution tests)
4. Open PR

---

## License

MIT — see `LICENSE`.

---

## Author

**Moksh Malde** — security tinkerer, bug bounty enthusiast.