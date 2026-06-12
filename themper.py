#!/usr/bin/env python3
import socket
import requests
import time
import sys
import ssl
import re
import json
from urllib.parse import urlparse
from datetime import datetime

G = '\033[92m'
Y = '\033[93m'
R = '\033[91m'
B = '\033[94m'
P = '\033[95m'
C = '\033[96m'
W = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

class ThemperV1:
    def __init__(self):
        self.score = 100
        self.vulns = []
        self.start_time = time.time()
        self.is_vercel = False
        self.home_html_hash = None

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

    def box(self, title, color=B):
        print(f"\n{color}{BOLD}┌{'─'*66}┐")
        print(f"│ {title:<64} │")
        print(f"└{'─'*66}┘{W}")

    def item(self, text, status="info"):
        icons = {"ok": f"{G}✓{W}", "warn": f"{Y}⚠{W}", "err": f"{R}✗{W}", "info": f"{C}◆{W}"}
        print(f" {icons[status]} {text}")

    def deduct_score(self, points, reason):
        self.score -= points
        if reason not in self.vulns:
            self.vulns.append(reason)

    def set_home_hash(self, html):
        """Guarda hash de la home pa' detectar catch-all"""
        self.home_html_hash = hash(html[:2000])

    def is_catchall(self, text):
        """Detecta si Vercel/Next devolvió la home en vez del archivo real"""
        if not self.home_html_hash: return False
        if hash(text[:2000]) == self.home_html_hash: return True
        if '<!doctype html>' in text.lower() and '<title>' in text.lower():
            if 'sauNuz project beta' in text: return True
        return False

    def get_dns_doh(self, domain, record_type):
        try:
            url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}"
            headers = {"accept": "application/dns-json"}
            r = requests.get(url, headers=headers, timeout=5)
            data = r.json()
            self.item(f"DNS DoH Raw {record_type}: {C}{json.dumps(data)[:80]}...{W}", "info")
            if "Answer" in data:
                for answer in data["Answer"]:
                    self.item(f"{record_type}: {C}{answer['data']}{W}", "ok")
            else:
                self.item(f"No hay registros {record_type} públicos", "warn")
        except Exception as e:
            self.item(f"Error DNS {record_type}: {e}", "err")

    def check_robots_sitemap(self, url):
        self.box("robots.txt & sitemap.xml", B)
        for file in ['robots.txt', 'sitemap.xml']:
            try:
                r = requests.get(f"{url}/{file}", timeout=3)
                if r.status_code == 200 and not self.is_catchall(r.text):
                    lines = len(r.text.split('\n'))
                    self.item(f"{file}: {G}Encontrado{W} - {lines} líneas", "ok")
                    print(f"{DIM}{r.text[:300]}...{W}")
                    if file == 'robots.txt' and 'Disallow' in r.text:
                        disallow = re.findall(r'Disallow: (.+)', r.text)
                        if disallow:
                            self.item(f"Rutas ocultas: {Y}{', '.join(disallow[:5])}{W}", "warn")
                else:
                    self.item(f"{file}: No encontrado o es catch-all", "info")
            except: pass

    def check_cors(self, url):
        self.box("CORS Misconfiguration", Y)
        try:
            headers = {'Origin': 'https://evil.com'}
            r = requests.get(url, headers=headers, timeout=5)
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')

            if acao == '*':
                self.item("Access-Control-Allow-Origin: * detectado", "warn")
                self.deduct_score(5, "CORS wildcard")
            elif acao == 'https://evil.com':
                self.item("CRÍTICO: CORS refleja Origin malicioso", "err")
                self.deduct_score(20, "CORS refleja Origin")

            if acac.lower() == 'true' and acao == '*':
                self.item("CRÍTICO: ACAO:* + ACAC:true = exploit", "err")
                self.deduct_score(25, "CORS + Credentials wildcard")
            else:
                self.item("CORS parece seguro", "ok")
        except:
            self.item("No se pudo probar CORS", "warn")

    def check_sourcemaps(self, html, url):
        self.box("Source Maps Expuestos", Y)
        js_urls = re.findall(r'<script.*?src="([^"]+\.js)"', html)
        exposed = 0

        for js_url in js_urls[:3]:
            try:
                full_url = js_url if js_url.startswith('http') else url.rstrip('/') + '/' + js_url.lstrip('/')
                map_url = full_url + '.map'
                r = requests.get(map_url, timeout=3)
                if r.status_code == 200 and '"sources"' in r.text:
                    self.item(f"SourceMap expuesto: {R}{js_url}.map{W}", "err")
                    self.deduct_score(10, f"SourceMap expuesto {js_url}")
                    exposed += 1
            except: pass

        if exposed == 0:
            self.item("No se detectaron sourcemaps públicos", "ok")

    def detectar_framework(self, html, headers):
        frameworks = {}
        if '__NEXT_DATA__' in html:
            frameworks['Next.js'] = "Detectado"
            build = re.search(r'"buildId":"([^"]+)"', html)
            if build: frameworks['Next.js Build'] = build.group(1)[:8]
        if 'id="__nuxt"' in html or '/_nuxt/' in html:
            frameworks['Nuxt.js'] = "Detectado"
        if 'astro-' in html: frameworks['Astro'] = "Detectado"
        if 'id="svelte' in html: frameworks['SvelteKit'] = "Detectado"
        server = str(headers.get('Server', '')).lower()
        if 'vercel' in server:
            frameworks['Hosting'] = "Vercel"
            self.is_vercel = True
        if 'cloudflare' in server: frameworks['Hosting'] = "Cloudflare"
        if 'netlify' in server: frameworks['Hosting'] = "Netlify"
        return frameworks

    def check_cves(self, frameworks):
        self.box("Análisis de CVEs Conocidos", R)
        if 'Next.js' in frameworks:
            self.item("Next.js detectado - CVEs críticas a revisar:", "warn")
            self.item("CVE-2023-46298: Middleware Bypass - <13.4.20", "info")
            self.item("CVE-2024-34351: SSRF en Server Actions - <14.1", "info")
            self.item("CVE-2024-46982: Cache Poisoning - <14.2.7", "info")
            self.deduct_score(5, "Verificar versión Next.js")
        elif 'Nuxt.js' in frameworks:
            self.item("CVE-2023-3224: XSS en Nuxt 2 - <2.16.3", "info")
            self.deduct_score(3, "Verificar versión Nuxt.js")
        else:
            self.item("No se detectaron frameworks con CVEs críticos conocidos", "ok")

    def test_rate_limit(self, url):
        self.box("Test de Rate Limiting", Y)
        blocked = 0
        self.item("Enviando 20 requests en 2 segundos...", "info")
        for i in range(20):
            try:
                r = requests.get(url, timeout=2)
                if r.status_code == 429: blocked += 1
            except: pass

        if blocked == 0:
            self.item("Sin Rate Limit - Vulnerable a DoS/Fuerza bruta", "err")
            self.deduct_score(15, "Sin Rate Limiting")
        elif blocked < 10:
            self.item(f"Rate Limit débil - Solo {blocked}/20 bloqueadas", "warn")
            self.deduct_score(8, "Rate Limit débil")
        else:
            self.item(f"Rate Limit activo - {blocked}/20 bloqueadas", "ok")

    def check_exposed_files(self, url):
        self.box("Archivos Sensibles Expuestos", R)
        sensitive = ['.env', '.git/config', '.DS_Store', 'wp-config.php', 'config.json', 'backup.zip', 'database.sql', '.htaccess', 'phpinfo.php']
        found = 0

        for file in sensitive:
            try:
                r = requests.get(f"{url}/{file}", timeout=3, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 20:
                    if self.is_catchall(r.text):
                        self.item(f"{file}: {Y}Catch-all detectado{W}", "warn")
                    else:
                        self.item(f"CRÍTICO: {R}{file} expuesto{W}", "err")
                        self.deduct_score(30, f"{file} público")
                        print(f"{DIM}Contenido: {r.text[:200]}...{W}")
                        found += 1
            except: pass

        if found == 0:
            self.item("No se encontraron archivos sensibles expuestos reales", "ok")

    def scan_js_secrets(self, html, url):
        self.box("Secrets en Frontend", R)
        js_urls = re.findall(r'<script.*?src="([^"]+\.js)"', html)
        patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Google API': r'AIza[0-9A-Za-z\-_]{35}',
            'Stripe Live': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Test': r'sk_test_[0-9a-zA-Z]{24}',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'Generic Secret': r'["\']?[a-zA-Z0-9_]*secret[a-zA-Z0-9_]*["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{16,}["\']'
        }

        found = 0
        for js_url in js_urls[:5]:
            try:
                full_url = js_url if js_url.startswith('http') else url.rstrip('/') + '/' + js_url.lstrip('/')
                js = requests.get(full_url, timeout=5).text
                for name, pattern in patterns.items():
                    matches = re.findall(pattern, js)
                    if matches:
                        self.item(f"Posible {R}{name} filtrado{W} en {js_url}", "err")
                        self.item(f"Match: {C}{matches[0][:30]}...{W}", "info")
                        self.deduct_score(20, f"{name} en JS")
                        found += 1
            except: pass

        if found == 0:
            self.item("No se detectaron secrets obvios en JS", "ok")

    def analizar_seguridad(self, headers, html, url):
        self.box("ANÁLISIS DE VULNERABILIDADES", R)

        print(f"\n{C}{BOLD}TODOS LOS HEADERS HTTP{W}")
        for k, v in headers.items():
            print(f"{DIM}{k}: {v}{W}")

        print(f"\n{C}{BOLD}Tabla de Cabeceras de Seguridad{W}")
        print(f"{DIM}{'Cabecera':<30} {'Estado':<15} {'Impacto'}{W}")
        print(f"{DIM}{'─'*65}{W}")

        sec_headers = {
            'X-Frame-Options': ['Clickjacking', 10],
            'X-Content-Type-Options': ['MIME Sniffing', 5],
            'Strict-Transport-Security': ['SSL Stripping', 10],
            'Content-Security-Policy': ['XSS/Inyección', 20],
            'Referrer-Policy': ['Fuga de Referrer', 5],
            'Permissions-Policy': ['Abuso de APIs', 5]
        }

        for h, (vuln, points) in sec_headers.items():
            if h not in headers:
                print(f"{R}{h:<30} {'FALTANTE':<15} {vuln}{W}")
                self.deduct_score(points, f"Falta {h}")
            else:
                val = headers[h][:40] + "..." if len(headers[h]) > 40 else headers[h]
                print(f"{G}{h:<30} {'PRESENTE':<15} {C}{val}{W}")

        print(f"\n{C}{BOLD}Cookies y Fuga de Info{W}")
        if 'Set-Cookie' in headers:
            c = headers['Set-Cookie']
            self.item(f"Cookie detectada: {C}{c[:60]}...{W}", "info")
            if 'HttpOnly' not in c: self.item("Cookie sin HttpOnly", "err"); self.deduct_score(10, "Cookie sin HttpOnly")
            if 'Secure' not in c: self.item("Cookie sin Secure", "err"); self.deduct_score(10, "Cookie sin Secure")
            if 'SameSite' not in c: self.item("Cookie sin SameSite", "warn"); self.deduct_score(5, "Cookie sin SameSite")
        else:
            self.item("No se detectaron cookies", "ok")

        if 'X-Powered-By' in headers:
            self.item(f"X-Powered-By expone: {R}{headers['X-Powered-By']}{W}", "warn")
            self.deduct_score(3, "Fuga de info X-Powered-By")

        print(f"\n{C}{BOLD}Test XSS Básico{W}")
        try:
            payload = "<script>alert('themper')</script>"
            r = requests.get(f"{url}?themper={payload}", timeout=5)
            if payload in r.text:
                self.item("XSS Reflejado DETECTADO - CRÍTICO", "err")
                self.deduct_score(25, "XSS Reflejado")
            else:
                self.item("No se refleja payload XSS", "ok")
        except:
            self.item("No se pudo probar XSS", "warn")

    def export_json(self, domain):
        data = {
            "target": domain,
            "timestamp": datetime.now().isoformat(),
            "score": max(0, self.score),
            "risk_level": "LOW" if self.score >= 70 else "MEDIUM" if self.score >= 50 else "HIGH",
            "vulns": self.vulns,
            "scan_type": "themperV1.3_FULL",
            "duration_seconds": round(time.time() - self.start_time, 2)
        }
        filename = f"themper_{domain.replace('.', '_').replace(':', '_')}.json"
        with open(filename, 'w') as f: json.dump(data, f, indent=2)
        self.item(f"JSON exportado: {C}{filename}{W}", "ok")
        return data

    def generar_html(self, domain):
        html = f"""<!DOCTYPE html>
<html><head><title>themperV1 Report - {domain}</title>
<meta charset="UTF-8">
<style>
body{{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:20px}}
h1{{color:#f85149}}h2{{color:#58a6ff}}.ok{{color:#3fb950}}.warn{{color:#d29922}}.err{{color:#f85149}}
.score{{font-size:48px;font-weight:bold}}.box{{border:1px solid #30363d;padding:15px;margin:10px 0;border-radius:6px}}
ul{{list-style:none;padding:0}}li{{padding:5px 0}}.footer{{margin-top:30px;color:#8b949e;font-size:12px}}
</style></head><body>
<h1>themperV1 v1.3 Security Report</h1>
<div class="box"><h2>Target: {domain}</h2>
<p>Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p class="score {'ok' if self.score>70 else 'warn' if self.score>50 else 'err'}">Score: {max(0, self.score)}/100</p></div>
<div class="box"><h2>Vulnerabilidades Detectadas: {len(self.vulns)}</h2>
<ul>{"".join([f'<li class="err">✗ {v}</li>' for v in self.vulns]) if self.vulns else '<li class="ok">✓ Sin problemas detectados</li>'}</ul></div>
<div class="footer">Generado por themperV1.3 FULL - SauNuz Team</div>
</body></html>"""

        filename = f"themper_{domain.replace('.', '_').replace(':', '_')}.html"
        with open(filename, 'w', encoding='utf-8') as f: f.write(html)
        self.item(f"Reporte HTML guardado: {C}{filename}{W}", "ok")

    def run(self, url):
        self.banner()

        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            self.item("URL inválida. Usa https://", "err")
            return 1

        root_domain = ".".join(domain.split('.')[-2:]) if domain.count('.') > 1 else domain

        self.box(f"Target: {domain}", P)

        # 1. IP
        self.box("Resolución de IP", B)
        try:
            ip = socket.gethostbyname(domain)
            self.item(f"Host: {C}{domain}{W}", "ok")
            self.item(f"IP: {C}{ip}{W}", "ok")
        except Exception as e:
            self.item(f"Error resolviendo IP: {e}", "err")
            return 1

        # 2. SSL
        self.box("Certificado SSL/TLS", B)
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(10.0)
                s.connect((domain, 443))
                cert = s.getpeercert()
                issued_to = dict(x[0] for x in cert.get('subject', []))
                issued_by = dict(x[0] for x in cert.get('issuer', []))
                self.item(f"Emitido para: {C}{issued_to.get('commonName', 'N/A')}{W}", "ok")
                self.item(f"Emisor: {C}{issued_by.get('organizationName', 'N/A')}{W}", "ok")
                self.item(f"Válido hasta: {C}{cert.get('notAfter')}{W}", "ok")
        except:
            self.item("SSL Timeout normal en CDNs", "warn")
            self.deduct_score(5, "SSL handshake lento")

        # 3. DNS
        self.box(f"DNS Avanzado - {root_domain}", B)
        self.get_dns_doh(root_domain, "NS")
        self.get_dns_doh(root_domain, "TXT")
        self.get_dns_doh(root_domain, "MX")

        # 4. Headers + HTML
        self.box("Fingerprinting + WAF", B)
        try:
            start_req = time.time()
            r = requests.get(url, allow_redirects=True, timeout=10)
            req_time = round((time.time() - start_req) * 1000, 2)
            headers = r.headers
            html = r.text
            self.set_home_hash(html)
            self.item(f"Tiempo de respuesta: {C}{req_time}ms{W}", "info")
            self.item(f"Tamaño HTML: {C}{len(html)} bytes{W}", "info")
            self.item(f"Status Code: {C}{r.status_code}{W}", "info")
            if r.history:
                self.item(f"Redirects: {C}{len(r.history)} saltos{W}", "info")
                for i, resp in enumerate(r.history):
                    self.item(f" {i+1}. {resp.status_code} -> {resp.url}", "info")
            self.item(f"Server: {C}{headers.get('Server', 'N/A')}{W}", "info")
            waf = []
            s = str(headers).lower()
            if 'cf-ray' in s or 'cloudflare' in s: waf.append("Cloudflare")
            if 'x-vercel-id' in s: waf.append("Vercel")
            if 'x-amz-cf-id' in s: waf.append("AWS CloudFront")
            self.item(f"WAF/CDN: {C}{', '.join(waf) if waf else 'Ninguno detectado'}{W}", "info")
        except Exception as e:
            self.item(f"Error obteniendo datos: {e}", "err")
            return 1

        # 5. Framework + Título
        self.box("Stack Tecnológico", B)
        title = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        self.item(f"Título: {C}{title.group(1).strip() if title else 'N/A'}{W}", "info")
        frameworks = self.detectar_framework(html, headers)
        for k, v in frameworks.items():
            self.item(f"{k}: {C}{v}{W}", "info")
        if not frameworks:
            self.item("Stack oculto o personalizado", "info")

        # 6. robots.txt y sitemap
        self.check_robots_sitemap(url)

        # 7. Puertos
        self.box("Escaneo de Puertos", Y)
        self.item("IPs anycast solo exponen 80/443", "warn")
        for p, servicio in {80:'HTTP', 443:'HTTPS'}.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                if s.connect_ex((ip, p)) == 0:
                    self.item(f"Puerto {p} ({servicio}): {G}Abierto{W}", "ok")
            except: pass
            finally: s.close()

        # 8. CORS
        self.check_cors(url)

        # 9. Vulns
        self.analizar_seguridad(headers, html, url)

        # 10. CVEs
        self.check_cves(frameworks)

        # 11. Secrets en JS
        self.scan_js_secrets(html, url)

        # 12. Sourcemaps
        self.check_sourcemaps(html, url)

        # 13. Rate Limit
        self.test_rate_limit(url)

        # 14. Archivos expuestos
        self.check_exposed_files(url)

        # Score Final
        self.box("SCORE FINAL", P)
        self.score = max(0, self.score)
        color = G if self.score > 70 else Y if self.score > 50 else R
        print(f"\n{color}{BOLD} Score de Seguridad: {self.score}/100{W}")

        if self.score >= 90:
            self.item("RIESGO NULO - Excelente hardening", "ok")
        elif self.score >= 70:
            self.item("RIESGO BAJO - Algunos headers faltantes", "warn")
        elif self.score >= 50:
            self.item("RIESGO MEDIO - Vulnerabilidades corregibles", "warn")
        else:
            self.item("RIESGO ALTO - Parchear urgente", "err")

        # Export
        self.box("Exportar Reportes", C)
        self.export_json(domain)
        self.generar_html(domain)

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

if __name__ == '__main__':
    if len(sys.argv)!= 2:
        print(f"{R}Uso: python themper.py https://ejemplo.com{W}")
        sys.exit(1)

    themper = ThemperV1()
    exit_code = themper.run(sys.argv[1])
    sys.exit(exit_code)