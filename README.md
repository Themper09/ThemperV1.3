# ThemperV1.3 — Web Security Scanner & Auditor

ThemperV1 is a modular web security scanning tool developed by SauNuz Team. It audits HTTP security headers, DNS records, SSL/TLS certificates, exposed files, CORS misconfigurations, JavaScript secrets, source maps, rate limiting, and known CVEs.

---

## Features

| Module                | Description                                                      |
|-----------------------|------------------------------------------------------------------|
| DNS Recon             | Resolves NS, TXT, MX records via Cloudflare DoH                  |
| SSL/TLS               | Inspects certificate issuer, subject, and expiration             |
| Security Headers      | Checks X-Frame-Options, CSP, HSTS, and 3 additional headers     |
| CORS Audit            | Detects wildcard or origin-reflecting Access-Control rules       |
| Framework Fingerprint | Detects Next.js, Nuxt, Astro, SvelteKit, and hosting CDNs       |
| CVE Lookup            | Flags known vulnerabilities based on detected framework          |
| JS Secrets Scan       | Scans bundled JavaScript for AWS keys, Stripe tokens, Google API keys |
| Source Maps           | Detects publicly exposed .js.map files                           |
| Rate Limit Test       | Sends rapid requests to assess brute-force protection            |
| Exposed Files         | Probes for .env, .git/config, wp-config.php, and more            |
| XSS Probe             | Tests for reflected cross-site scripting                         |
| Port Scan             | Checks TCP ports 80 and 443                                      |
| robots.txt / sitemap  | Discovers hidden routes via Disallow directives                  |
| Reports               | Exports results as JSON and HTML                                 |

---

## Quick Start

```bash
git clone https://github.com/SauNuz/themperV1.3.git
cd themperV1.3
pip install -r requirements.txt
python themper.py https://example.com
```

Or using the module directly:

```bash
python -m src.main https://example.com
```

---

## Example Output

```
Score de Seguridad: 80/100
RIESGO BAJO - Algunos headers faltantes

Target: example.com
Score: 80/100
Riesgo: BAJO
Vulns: 2
Tiempo: 30.0s
```

Reports are saved automatically:

```
themper_example_com.json
themper_example_com.html
```

---

## Project Structure

```
themperV1.3/
├── src/
│   ├── main.py              # CLI entry point
│   ├── core/
│   │   ├── colors.py        # ANSI color helpers
│   │   └── scanner.py       # Orchestrator
│   ├── modules/
│   │   ├── dns.py           # DNS resolution & DoH queries
│   │   ├── ssl_check.py     # SSL/TLS certificate inspection
│   │   ├── headers.py       # Security headers & XSS test
│   │   ├── framework.py     # Framework & CDN detection
│   │   ├── cve_check.py     # Known CVE cross-reference
│   │   ├── cors.py          # CORS misconfiguration check
│   │   ├── rate_limit.py    # Brute-force protection test
│   │   ├── exposed_files.py # Sensitive file discovery
│   │   ├── js_secrets.py    # Secret scanning in JavaScript
│   │   ├── sourcemaps.py    # Source map exposure detection
│   │   ├── robots.py        # robots.txt & sitemap.xml audit
│   │   └── ports.py         # TCP port scan (80/443)
│   └── controllers/
│       └── report.py        # JSON & HTML report generation
├── themper.py               # Legacy single-file entry point
├── requirements.txt
└── README.md
```

---

## Scoring

| Score     | Risk Level | Description              |
|-----------|------------|--------------------------|
| 90–100    | Null       | Excellent hardening      |
| 70–89     | Low        | Minor headers missing    |
| 50–69     | Medium     | Fixable vulnerabilities  |
| 0–49      | High       | Urgent patching required |

---

## Requirements

- Python 3.8+
- requests
- urllib3

---

## License

MIT — see [LICENSE](LICENSE).

---

SauNuz Team
