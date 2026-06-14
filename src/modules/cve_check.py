from src.core.colors import item, R, W, box


def check_cves(frameworks, scanner):
    box("Análisis de CVEs Conocidos", R)
    if 'Next.js' in frameworks:
        item("Next.js detectado - CVEs críticas a revisar:", "warn")
        item("CVE-2023-46298: Middleware Bypass - <13.4.20", "info")
        item("CVE-2024-34351: SSRF en Server Actions - <14.1", "info")
        item("CVE-2024-46982: Cache Poisoning - <14.2.7", "info")
        scanner.deduct_score(5, "Verificar versión Next.js")
    elif 'Nuxt.js' in frameworks:
        item("CVE-2023-3224: XSS en Nuxt 2 - <2.16.3", "info")
        scanner.deduct_score(3, "Verificar versión Nuxt.js")
    else:
        item("No se detectaron frameworks con CVEs críticos conocidos", "ok")
