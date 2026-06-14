import re
import requests
from src.core.colors import item, R, Y, C, BOLD, W, box


def parse_version(text, pattern):
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1) if m else None


def version_tuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0,)


VULN_LIBS = [
    ("jQuery", r'jquery[.-]?([\d.]+)\.min\.js', [
        ("<1.12.4", "CVE-2020-11023 (XSS) / CVE-2020-11022 (XSS)"),
        ("<3.0.0", "CVE-2019-11358 (Prototype pollution)"),
        ("<3.5.0", "CVE-2020-11023 (XSS)"),
    ]),
    ("React", r'react(?:\.min)?[./-]([\d.]+)', [
        ("<16.8.0", "CVE-2018-6341 (SSR XSS)"),
        ("<16.13.1", "CVE-2020-10001 (SSRF)"),
    ]),
    ("Vue", r'vue[.-]?([\d.]+)\.min\.js', [
        ("<2.6.12", "CVE-2020-22768 (XSS)"),
        ("<3.0.10", "CVE-2021-23353 (XSS)"),
    ]),
    ("Angular", r'angular[.-]?([\d.]+)\.min\.js', [
        ("<1.8.0", "CVE-2020-7676 (XSS)"),
        ("<1.8.3", "CVE-2022-25869 (Prototype pollution)"),
    ]),
    ("Bootstrap", r'bootstrap[.-]?([\d.]+)\.min\.css', [
        ("<3.4.1", "CVE-2019-8331 (XSS)"),
        ("<4.3.1", "CVE-2019-8331 (XSS)"),
    ]),
    ("Lodash", r'lodash[.-]?([\d.]+)\.min\.js', [
        ("<4.17.21", "CVE-2021-23337 (Prototype pollution)"),
        ("<4.17.11", "CVE-2019-10744 (Prototype pollution)"),
    ]),
    ("Moment.js", r'moment[.-]?([\d.]+)\.min\.js', [
        ("<2.29.4", "CVE-2022-24785 (ReDoS)"),
    ]),
    ("DOMPurify", r'dompurify[.-]?([\d.]+)\.min\.js', [
        ("<2.0.17", "CVE-2021-27323 (XSS bypass)"),
    ]),
    ("socket.io", r'socket\.io[.-]?([\d.]+)\.min\.js', [
        ("<2.4.0", "CVE-2020-28489 (XSS)"),
    ]),
    ("Chart.js", r'chart[.-]?([\d.]+)\.min\.js', [
        ("<2.9.4", "CVE-2020-27511 (Prototype pollution)"),
    ]),
]


def check_librerias_vulnerables(html, url, scanner, session=None):
    box("Librerías JavaScript Vulnerables", R)
    http = session or requests
    found = 0
    fetched_html = None

    for lib_name, pattern, vulns in VULN_LIBS:
        version = parse_version(html, pattern)
        if not version:
            if fetched_html is None:
                try:
                    fetched_html = http.get(url, timeout=3).text
                except Exception:
                    continue
            version = parse_version(fetched_html, pattern)

        if version:
            item(f"{C}{lib_name}{W} v{version} detectada", "info")
            for constraint, desc in vulns:
                threshold = constraint.replace("<=", "").replace("<", "")
                if version_tuple(version) < version_tuple(threshold):
                    item(f"  {R}VULNERABLE:{W} {desc}", "err")
                    scanner.deduct_score(8, f"{lib_name} {version}: {desc}")
                    found += 1
                    break

    if found == 0:
        item("No se detectaron librerías con CVEs conocidos", "ok")
