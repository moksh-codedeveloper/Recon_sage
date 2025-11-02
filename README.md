# Recon_sage 🔍⚡

Fast async directory enumeration tool for bug bounty hunters and penetration testers.

![Version](https://img.shields.io/badge/version-1.0.1-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen)

## 🚀 Features

- ⚡ **Blazing Fast** - 50+ requests/second with async HTTP
- 🐳 **Docker Ready** - One command deployment
- 🎯 **Flexible** - Configurable wordlists and output paths
- 📊 **JSON Logging** - Structured output for easy parsing
- 🔒 **Rate Limiting** - Semaphore-based concurrency control (100 concurrent)
- 💪 **Production Ready** - Built with FastAPI and httpx

## 📦 Installation

### Using Docker (Linux - Recommended)
```bash
docker run -d --name reconsage \
  --network host \
  -v /usr/share/seclists:/usr/share/seclists:ro \
  -v ~/recon_logs:/app/result_log \
  mokshmalde/reconsage:v1.0.1
```

**What this does:**
- Uses host network for better performance
- Mounts SecLists wordlists (read-only)
- Saves results to `~/recon_logs` on your machine

### Local Installation (Windows/Linux/Mac)
```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/ReconSage.git
cd ReconSage

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

## 🎯 Usage

### Quick Start

Once running, the API will be available at `http://localhost:8000`

**View API documentation:**
```
http://localhost:8000/docs
```

### Basic Scan
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://testphp.vulnweb.com/",
    "wordlist_path_1": "/usr/share/seclists/Discovery/Web-Content/common.txt"
  }'
```

### Advanced Scan (Two Wordlists)
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://example.com/",
    "wordlist_path_1": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "wordlist_path_2": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "output_subfolder": "my_scans",
    "output_filename": "scan_results"
  }'
```

### Using Postman

1. **Method:** POST
2. **URL:** `http://localhost:8000/scan`
3. **Headers:** `Content-Type: application/json`
4. **Body (JSON):**
```json
{
  "target": "http://localhost:3000/",
  "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
  "wordlist_2" : "<Optional If you have then pass>",
  "output_file_path" : "/path/to/file_name",
  "output_file_name" : "file_name.json"
}
```

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information and status |
| `/scan` | POST | Start directory enumeration scan |

## 🔧 Configuration

### Scan Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ Yes | - | Target URL (must include http:// or https://) |
| `wordlist_path_1` | string | ✅ Yes | - | Path to first wordlist |
| `wordlist_path_2` | string | ❌ No | null | Path to second wordlist |
| `output_subfolder` | string |✅ Yes | - | Path for results |
| `output_filename` | string | ✅ Yes | - | Output filename With .json |

### Response Format
```json
{
    "message": "the result is as you can see here in the given lists",
    "present_counts": 15,
    "not_present_counts": 485,
    "count_of_errors_that_came": 2,
    "timestamps": "2024-11-01_20-30-45"
}
```

## 🐳 Docker Guide

### Pull Image
```bash
docker pull mokshmalde/reconsage:v1.0.1
```

### Run Container

**Linux (with SecLists):**
```bash
docker run -d --name reconsage \
  --network host \
  -v /usr/share/seclists:/usr/share/seclists:ro \
  -v ~/recon_logs:/app/result_log \
  mokshmalde/reconsage:v1.0.1
```

**Without SecLists (use your own wordlists):**
```bash
docker run -d --name reconsage \
  --network host \
  -v /path/to/wordlists:/wordlists:ro \
  -v /path/to/logs:/app/result_log \
  mokshmalde/reconsage:v1.0.1
```

### View Logs
```bash
docker logs -f reconsage
```

### Stop Container
```bash
docker stop reconsage
docker rm reconsage
```

## 📈 Performance

- **Speed:** 50-100 requests/second
- **Concurrency:** 100 simultaneous connections
- **Efficiency:** ~5,800 URLs scanned in ~2 minutes
- **Comparison:** Comparable to Gobuster, faster than Dirb

### Benchmark Example

**Test:** 5,842 URLs against `http://localhost:3000/`
- **Time:** 1 minute 49 seconds
- **Speed:** ~53 requests/second
- **Memory:** ~50MB
- **CPU:** Low usage (async I/O)

## 🛠️ Requirements

### For Docker
- Docker installed
- 50MB disk space
- Network access

### For Local Installation
- Python 3.11+
- pip
- Dependencies:
  - fastapi
  - uvicorn
  - httpx
  - pydantic

## 📝 Example Output

**Terminal response: (example)**
```json
{
    "present_counts": 12,
    "not_present_counts": 388,
    "count_of_errors_that_came" : 2,
    "timestamps": "2024-11-01_20-15-30"
}
```

**JSON log file** (`~/recon_logs/scans/scan_20241101_201530.json`):
```json
{
  "message": "comprehensive list of targets",
  "present targets": [
    "http://testphp.vulnweb.com/admin",
    "http://testphp.vulnweb.com/login",
    "http://testphp.vulnweb.com/images"
  ],
  "not present targets": [...],
  "errors_that_came": [],
  "timestamps": "2024-11-01_20-15-30"
}
```

## 🚨 Important Notes

### Legal Usage
⚠️ **Only scan targets you have permission to test!**

Use only on:
- Your own systems
- Bug bounty programs
- Authorized penetration tests
- Legal test environments (testphp.vulnweb.com, etc.)

### Rate Limiting
The tool uses semaphore-based rate limiting (100 concurrent). Adjust in code if needed:
```python
sem = asyncio.Semaphore(100)  # Change value
```

## 🗺️ Roadmap

Planned features for future releases:

- [ ] Wildcard detection (v1.1.0)
- [ ] DNS validation
- [ ] False positive filtering
- [ ] Web UI dashboard
- [ ] Multi-target scanning
- [ ] Custom headers support
- [ ] Authentication methods
- [ ] Export formats (CSV, XML)
- [ ] Windows-specific Docker image
- [ ] Integration with other tools

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Built by Moksh Malde**
- 18-year-old security enthusiast
- Living the unscripted polymath life
- Passionate about bug bounty and offensive security

## 🙏 Acknowledgments

- FastAPI for the amazing framework
- httpx for async HTTP capabilities
- The bug bounty community for inspiration
- SecLists for comprehensive wordlists

## ⭐ Show Your Support

If you find this tool useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs
- 💡 Suggesting features
- 📢 Sharing with the community

---

**Made with ❤️ and lots of ☕ by a passionate 18-year-old hacker**