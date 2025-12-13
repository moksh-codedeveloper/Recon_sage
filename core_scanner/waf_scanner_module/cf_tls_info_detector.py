def cloudflare_detector(self, tls_info: dict):
    """Returns confidence score + matched fields"""
    # ... (your signature lists) ...
    # ✅ ADD THESE:
    cf_tls_version = ["TLSv1.2", "TLSv1.3"]
    cf_cipher_suite = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305"
    ]
    cf_issuer_o = [
        "Cloudflare, Inc.",
        "Cloudflare Inc",
        "Google Trust Services LLC",
        "Google Trust Services"
    ]
    cf_issuer_cn = [
        "Cloudflare Inc ECC CA-3",
        "Cloudflare Inc ECC CA-2",
        "Cloudflare Inc RSA CA-1",
        "GTS CA 1C3"
    ]
    cf_subject_cn = [
        "sni.cloudflaressl.com",
        "*.cloudflaressl.com",
        "cloudflare.com"
    ]
    cf_san_patterns = [
        ".cloudflaressl.com",
        "sni.cloudflaressl.com",
        ".cloudflare.com"
    ]
    cf_signature_algorithm = [
        "sha256WithRSAEncryption",
        "ecdsa-with-SHA256",
        "ecdsa-with-SHA384"
    ]
    
    matches = {
        "confidence_score": 0,
        "matched_fields": {},
        "waf_detected": False
    }
    
    if tls_info.get("tls_version") in cf_tls_version:
        matches["confidence_score"] += 10
        matches["matched_fields"]["tls_version"] = tls_info["tls_version"]
    
    # Cipher Suite (medium weight)
    
    if tls_info.get("cipher_suite") in cf_cipher_suite:
        matches["confidence_score"] += 20
        matches["matched_fields"]["cipher_suite"] = tls_info["cipher_suite"]
    
    # Issuer (HIGH weight - most reliable)
    
    issuer_dict = self._parse_cert_field(tls_info.get("issuer", []))
    issuer_o = issuer_dict.get('O', '')
    issuer_cn = issuer_dict.get('CN', '')
    
    if issuer_o in cf_issuer_o:
        matches["confidence_score"] += 40
        matches["matched_fields"]["issuer_o"] = issuer_o
    
    if issuer_cn in cf_issuer_cn:
        matches["confidence_score"] += 30
        matches["matched_fields"]["issuer_cn"] = issuer_cn
    
    # Subject CN (medium weight)
    
    subject_dict = self._parse_cert_field(tls_info.get("subject", []))
    subject_cn = subject_dict.get('CN', '')
    
    if subject_cn in cf_subject_cn:
        matches["confidence_score"] += 25
        matches["matched_fields"]["subject_cn"] = subject_cn
    # SAN patterns (medium weight)
    san_matched = []
    for san_entry in tls_info.get("san", []):
        if len(san_entry) == 2 and san_entry[0] == 'DNS':
            domain = san_entry[1]
            for pattern in cf_san_patterns:
                if pattern in domain:
                    san_matched.append(domain)
                    break
                
    if san_matched:
        matches["confidence_score"] += 25
        matches["matched_fields"]["san"] = san_matched
    # Signature algorithm (low weight)
    if tls_info.get("sign_algo") in cf_signature_algorithm:
        matches["confidence_score"] += 10
        matches["matched_fields"]["sign_algo"] = tls_info["sign_algo"]
    # Detection threshold: 50+ = detected
    if matches["confidence_score"] >= 50:
        matches["waf_detected"] = True
        matches["waf_name"] = "Cloudflare"

    return matches