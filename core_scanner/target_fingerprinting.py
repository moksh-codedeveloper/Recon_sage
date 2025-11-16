import hashlib
import httpx
class PassiveFingerprint:
    def __init__(self, target, timeout):
        self.target = target
        self.timeout = timeout

    def wordlist_data_extractor(self, wordlist):
        data = []
        with open(wordlist, "r", encoding='utf-8') as f:
            for line in f:
                s = line.strip()
                if s :
                    data.append(s)
        return data

    async def scan_data(self, domain):
        subdomain_target = self.target + domain
        async with httpx.AsyncClient() as client:
            response = await client.get(subdomain_target)
            status_code = response.status_code
            headers = response.headers
            body_text = response.text
            hashed_body = self.hash_snippet(body=body_text)
            latency_ms = response.elapsed.total_seconds() * 1000
            return{
                "status_code" : status_code,
                "headers" : headers,
                "hashed_body" : hashed_body,
                "latency_ms" : latency_ms,
                "response_object" : response,
                "content_length" : len(response.text),
                "cookies" : response.cookies.jar,
                "http_version" : response.http_version,
                "charset" : response.encoding,
                "content_type": response.headers.get("Content-Type"),
                "redirect_chain": [str(r.url) for r in response.history],
                "server": response.headers.get("Server"),
                "powered_by": response.headers.get("X-Powered-By"),
                "cdn": response.headers.get("Via") or response.headers.get("CF-Ray"),
                "tls": {
                    "version": response.extensions.get("tls_version"),
                    "cipher": response.extensions.get("tls_cipher_suite"),
                    "peer_cert" : response.extensions.get("tls_peer_cert")
                },
                "set_cookies" : response.headers.get("Set-Cookie"),
                "content_security_policy" : response.headers.get("Content-Security-Policy"),
                "x_frame_options" : response.headers.get("X-Frame-Options"),
                "x_content_type_options" : response.headers.get("X-Content-Type-Options"),
                "strict_transport_security" : response.headers.get("Strict-Transport-Security")
            }
    def hash_snippet(self, body, length=300):
        if isinstance(body, bytes):
            snippet = body[:length]
            return hashlib.sha256(snippet).hexdigest()
        else:
            snippet = body[:length]
            return hashlib.sha256(snippet.encode()).hexdigest()