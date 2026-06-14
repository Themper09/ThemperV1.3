import time
import socket
import requests
import re
from urllib.parse import urlparse

from src.core.colors import G, Y, R, B, C, P, BOLD, DIM, W, box, item
from src.modules.dns import get_dns_doh
from src.modules.ssl_check import check_ssl
from src.modules.framework import detectar_framework
from src.modules.headers import check_security_headers
from src.modules.cve_check import check_cves
from src.modules.cors import check_cors
from src.modules.rate_limit import test_rate_limit
from src.modules.exposed_files import check_exposed_files
from src.modules.js_secrets import scan_js_secrets
from src.modules.sourcemaps import check_sourcemaps
from src.modules.robots import check_robots_sitemap
from src.modules.ports import scan_ports
from src.modules.grid_expuesto import check_grid_expuesto
from src.modules.librerias_vulnerables import check_librerias_vulnerables
from src.controllers.report import export_json, generar_html


class ThemperV1:
    def __init__(self):
        self.score = 100
        self.vulns = []
        self.start_time = time.time()
        self.is_vercel = False
        self.home_html_hash = None

    def deduct_score(self, points, reason):
        self.score -= points
        if reason not in self.vulns:
            self.vulns.append(reason)

    def set_home_hash(self, html):
        self.home_html_hash = hash(html[:2000])

    def is_catchall(self, text):
        if not self.home_html_hash:
            return False
        if hash(text[:2000]) == self.home_html_hash:
            return True
        if '<!doctype html>' in text.lower() and '<title>' in text.lower():
            if 'sauNuz project beta' in text:
                return True
        return False

    def banner(self):
        print(f"""{B}{BOLD}
╔══════════════════════════════════════════════════════════════════╗
║ ████████╗██╗ ██╗███████╗███╗ ███╗██████╗ ███████╗██████╗ ║
║ ╚══██╔══╝██║ ██║██╔════╝████╗ ████║██╔══██╗██╔════╝██╔══██╗ ║
║ ██║ ███████║█████╗ ██╔████╔██║██████╔╝█████╗ ██████╔╝ ║
║ ██║ ██╔══██║██╔══╝ ██║╚██╔╝██║██╔═══╝ ██╔══██╗ ║
║ ██║ ██║ ██║███████╗██║ ╚═╝ ██║██║ ███████╗██║ ██║ ║
║ ╚═╝╚══════╝╚═╝ ╚═╝╚═╝ ╚══════╝╚═╝ ╚═╝ ║
║ ║
║ {W}{BOLD}themperV1{W}{DIM} - Web Security Scanner & Auditor{W}{B}{BOLD} ║
║ {DIM}Headers, CVEs, Secrets, Archivos, DNS, CORS, Sourcemaps{W}{B}{BOLD} ║
║ ║
║ {C}by SauNuz Team{W}{B}{BOLD} - v1.3 FULL{W}{B}{BOLD} ║
╚══════════════════════════════════╝{W}
        """)

    def run(self, url=None, export='ask'):
        self.banner()

        if not url:
            print(f"{'':>30}{BOLD}Ingresa la URL a escanear{W}")
            print(f"{'':>26}{'─'*40}")
            url = input(f"{'':>32}{C}URL:{W} ").strip()
            if not url:
                item("No ingresaste ninguna URL", "err")
                return 1

        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            item("URL inválida. Usa https://", "err")
            return 1

        root_domain = ".".join(domain.split('.')[-2:]) if domain.count('.') > 1 else domain

        session = requests.Session()

        box(f"Target: {domain}", P)

        # 1. IP
        box("Resolución de IP")
        try:
            ip = socket.gethostbyname(domain)
            item(f"Host: {C}{domain}{W}", "ok")
            item(f"IP: {C}{ip}{W}", "ok")
        except Exception as e:
            item(f"Error resolviendo IP: {e}", "err")
            return 1

        # 2. SSL
        try:
            ssl_ok = check_ssl(domain)
            if not ssl_ok:
                self.deduct_score(5, "SSL handshake lento")
        except Exception:
            item("Error en módulo SSL", "err")

        # 3. DNS
        box(f"DNS Avanzado - {root_domain}")
        for rt in ("NS", "TXT", "MX"):
            try:
                get_dns_doh(session, root_domain, rt)
            except Exception:
                pass

        # 4. Headers + HTML
        box("Fingerprinting + WAF")
        try:
            start_req = time.time()
            r = session.get(url, allow_redirects=True, timeout=10)
            req_time = round((time.time() - start_req) * 1000, 2)
            headers = r.headers
            html = r.text
            self.set_home_hash(html)
            item(f"Tiempo de respuesta: {C}{req_time}ms{W}", "info")
            item(f"Tamaño HTML: {C}{len(html)} bytes{W}", "info")
            item(f"Status Code: {C}{r.status_code}{W}", "info")
            if r.history:
                item(f"Redirects: {C}{len(r.history)} saltos{W}", "info")
                for i, resp in enumerate(r.history):
                    item(f" {i+1}. {resp.status_code} -> {resp.url}", "info")
            item(f"Server: {C}{headers.get('Server', 'N/A')}{W}", "info")
            waf = []
            s = str(headers).lower()
            if 'cf-ray' in s or 'cloudflare' in s:
                waf.append("Cloudflare")
            if 'x-vercel-id' in s:
                waf.append("Vercel")
            if 'x-amz-cf-id' in s:
                waf.append("AWS CloudFront")
            item(f"WAF/CDN: {C}{', '.join(waf) if waf else 'Ninguno detectado'}{W}", "info")
        except Exception as e:
            item(f"Error obteniendo datos: {e}", "err")
            return 1

        # 5. Framework
        box("Stack Tecnológico")
        title = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        item(f"Título: {C}{title.group(1).strip() if title else 'N/A'}{W}", "info")
        frameworks = detectar_framework(html, headers)
        for k, v in frameworks.items():
            item(f"{k}: {C}{v}{W}", "info")
        if not frameworks:
            item("Stack oculto o personalizado", "info")

        # 6-16. Módulos de análisis
        mods = [
            ("robots.txt", lambda: check_robots_sitemap(session, url, self)),
            ("Puertos", lambda: scan_ports(ip)),
            ("CORS", lambda: check_cors(session, url, self)),
            ("Headers", lambda: check_security_headers(headers, html, url, self, session)),
            ("CVEs", lambda: check_cves(frameworks, self)),
            ("Secrets JS", lambda: scan_js_secrets(html, url, self, session)),
            ("Sourcemaps", lambda: check_sourcemaps(html, url, self, session)),
            ("Rate Limit", lambda: test_rate_limit(session, url, self)),
            ("Archivos expuestos", lambda: check_exposed_files(session, url, self)),
            ("Grids expuestos", lambda: check_grid_expuesto(session, url, self)),
            ("Librerías vulnerables", lambda: check_librerias_vulnerables(html, url, self, session)),
        ]
        for name, fn in mods:
            try:
                fn()
            except Exception as e:
                item(f"Error en {name}: {e}", "err")

        # Score Final
        box("SCORE FINAL", P)
        self.score = max(0, self.score)
        color = G if self.score > 70 else Y if self.score > 50 else R
        print(f"\n{color}{BOLD} Score de Seguridad: {self.score}/100{W}")

        if self.score >= 90:
            item("RIESGO NULO - Excelente hardening", "ok")
        elif self.score >= 70:
            item("RIESGO BAJO - Algunos headers faltantes", "warn")
        elif self.score >= 50:
            item("RIESGO MEDIO - Vulnerabilidades corregibles", "warn")
        else:
            item("RIESGO ALTO - Parchear urgente", "err")

        # Export
        box("Exportar Reportes", C)
        if export == 'ask':
            resp = input(f"{'':>28}{C}¿Exportar HTML y JSON?{W} (s/N): ").strip().lower()
        else:
            resp = 's' if export == 'yes' else 'n'
        if resp == 's':
            export_json(domain, self.score, self.vulns, self.start_time)
            generar_html(domain, self.score, self.vulns)
        else:
            item("Exportación omitida", "warn")

        # Resumen final
        print(f"\n{B}{BOLD}{'═'*68}")
        print(f" RESUMEN THEMPER V1.3 FULL")
        print(f"{'═'*68}{W}")
        print(f" {C}Target:{W} {domain}")
        print(f" {C}Score:{W} {color}{self.score}/100{W}")
        print(f" {C}Riesgo:{W} {color}{'ALTO' if self.score<50 else 'MEDIO' if self.score<70 else 'BAJO'}{W}")
        print(f" {C}Vulns:{W} {R}{len(self.vulns)}{W}")
        print(f" {C}Tiempo:{W} {round(time.time() - self.start_time, 1)}s")
        print(f"{G}{BOLD}{'═'*68}")
        print(f" themperV1.3 SCAN COMPLETADO")
        print(f"{'═'*68}{W}\n")

        return 0 if self.score >= 70 else 1
