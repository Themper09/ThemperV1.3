import json
import time
from datetime import datetime
from src.core.colors import item, C, W
from src.core.descriptions import get_vuln_description


def export_json(domain, score, vulns, start_time):
    data = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "score": max(0, score),
        "risk_level": "LOW" if score >= 70 else "MEDIUM" if score >= 50 else "HIGH",
        "vulns": vulns,
        "scan_type": "themperV1.3_FULL",
        "duration_seconds": round(time.time() - start_time, 2)
    }
    filename = f"themper_{domain.replace('.', '_').replace(':', '_')}.json"
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    item(f"JSON exportado: {C}{filename}{W}", "ok")


def _vuln_li_html(v):
    desc = get_vuln_description(v)
    li = f'<li class="err">✗ <strong>{v}</strong>'
    if desc:
        li += f'<br><span style="color:#8b949e;font-size:11px">{desc}</span>'
    return li + '</li>'


def generar_html(domain, score, vulns):
    vulns_html = "".join(
        [_vuln_li_html(v) for v in vulns]
    ) if vulns else '<li class="ok">✓ Sin problemas detectados</li>'

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
<p class="score {'ok' if score>70 else 'warn' if score>50 else 'err'}">Score: {max(0, score)}/100</p></div>
<div class="box"><h2>Vulnerabilidades Detectadas: {len(vulns)}</h2>
<ul>{vulns_html}</ul></div>
<div class="footer">Generado por themperV1.3 FULL - SauNuz Team</div>
</body></html>"""

    filename = f"themper_{domain.replace('.', '_').replace(':', '_')}.html"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)
    item(f"Reporte HTML guardado: {C}{filename}{W}", "ok")
