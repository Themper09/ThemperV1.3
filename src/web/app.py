import json
import os
import uuid
import time
from datetime import datetime
from urllib.parse import urlparse

import requests
from flask import Flask, render_template, request, jsonify, Response, stream_with_context, send_file

from src.web.scan_runner import ScanRunner
from src.core.scanner import ThemperV1

IS_VERCEL = os.environ.get("VERCEL") == "1"

_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
app = Flask(__name__,
    static_folder=os.path.join(_root_dir, 'public', 'static'),
    template_folder='templates'
)

runner = ScanRunner()

def _kv_get(key):
    url = os.environ.get("VERCEL_KV_REST_API_URL")
    token = os.environ.get("VERCEL_KV_REST_API_TOKEN")
    if not url or not token:
        return None
    try:
        r = requests.get(f"{url}/get/{key}", headers={"Authorization": f"Bearer {token}"}, timeout=3)
        return r.json().get("result")
    except Exception:
        return None


def _kv_set(key, value):
    url = os.environ.get("VERCEL_KV_REST_API_URL")
    token = os.environ.get("VERCEL_KV_REST_API_TOKEN")
    if not url or not token:
        return
    try:
        requests.get(f"{url}/set/{key}/{value}", headers={"Authorization": f"Bearer {token}"}, timeout=3)
    except Exception:
        pass


# ── Rotas locales (con threading + SSE) ──────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def start_scan_local():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL requerida"}), 400
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    export = data.get("export", True)
    scan_id = uuid.uuid4().hex[:12]
    runner.start_scan(scan_id, url, export=export)
    return jsonify({"scan_id": scan_id})


@app.route("/scan/stream/<scan_id>")
def stream_scan(scan_id):
    q = runner.get_queue(scan_id)
    if q is None:
        return "Scan no encontrado", 404

    def generate():
        while True:
            if runner.is_done(scan_id) and q.empty():
                break
            try:
                line = q.get(timeout=0.3)
                yield f"data: {json.dumps({'type': 'line', 'text': line})}\n\n"
            except Exception:
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

        result = runner.get_result(scan_id)
        if result:
            # Quitar paths absolutos que no sirven en el frontend
            result_clean = {k: v for k, v in result.items() if k not in ('html_report', 'json_report')}
            yield f"data: {json.dumps({'type': 'result', 'result': result_clean})}\n\n"

        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/scan/<scan_id>/download")
def download_report_local(scan_id):
    result = runner.get_result(scan_id)
    if not result:
        return jsonify({"error": "Scan no encontrado o aun en progreso"}), 404

    report = {
        "target": result.get("domain", ""),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "score": result["score"],
        "risk_level": result["risk_level"],
        "vulns": result["vulns"],
        "scan_type": "themperV1.3_FULL",
        "duration_seconds": result["duration"],
    }
    return jsonify(report)


@app.route("/report/<scan_id>")
def view_report_local(scan_id):
    result = runner.get_result(scan_id)
    if not result:
        return jsonify({"error": "Scan no encontrado o aun en progreso"}), 404

    html = _generate_html(
        result.get("domain", "unknown"),
        result.get("score", 0),
        result.get("vulns", [])
    )
    return html, 200, {"Content-Type": "text/html"}


# ── Rotas Vercel (sin threading, con KV) ────────────────────────

@app.route("/api/scan", methods=["POST"])
def start_scan_vercel():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL requerida"}), 400
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    scan_id = uuid.uuid4().hex[:12]
    result = _run_sync(url, scan_id)

    _kv_set(f"scan:{scan_id}", json.dumps(result))

    return jsonify(result)


@app.route("/api/scan/<scan_id>/status")
def scan_status(scan_id):
    if not IS_VERCEL:
        return jsonify({"error": "KV no disponible"}), 503
    data = _kv_get(f"scan:{scan_id}")
    if not data:
        return jsonify({"error": "Scan no encontrado"}), 404
    return jsonify(json.loads(data))


@app.route("/api/report/<scan_id>")
def view_report_vercel(scan_id):
    if IS_VERCEL:
        data = _kv_get(f"scan:{scan_id}")
        if data:
            result = json.loads(data)
            if result.get("status") == "done":
                html = _generate_html(
                    result.get("domain", "unknown"),
                    result.get("score", 0),
                    result.get("vulns", [])
                )
                return html, 200, {"Content-Type": "text/html"}
            return jsonify({"error": "Scan aun en progreso"}), 202
    return jsonify({"error": "Reporte no disponible"}), 404


@app.route("/api/scan/<scan_id>/download")
def download_report_vercel(scan_id):
    if not IS_VERCEL:
        return jsonify({"error": "KV no disponible"}), 503
    data = _kv_get(f"scan:{scan_id}")
    if not data:
        return jsonify({"error": "Scan no encontrado"}), 404

    result = json.loads(data)
    report = {
        "target": result.get("domain", ""),
        "timestamp": datetime.now().isoformat(),
        "score": result.get("score", 0),
        "risk_level": result.get("risk_level", "ERROR"),
        "vulns": result.get("vulns", []),
        "scan_type": "themperV1.3_FULL",
        "duration_seconds": result.get("duration", 0),
    }
    return jsonify(report)


def _run_sync(url, scan_id):
    try:
        scanner = ThemperV1()
        exit_code = scanner.run(url, export='no')
        parsed = urlparse(url)
        domain = parsed.netloc

        return {
            "status": "done",
            "scan_id": scan_id,
            "score": max(0, scanner.score),
            "vulns": list(scanner.vulns),
            "risk_level": (
                "LOW" if scanner.score >= 70
                else "MEDIUM" if scanner.score >= 50
                else "HIGH"
            ),
            "duration": round(time.time() - scanner.start_time, 2),
            "exit_code": exit_code,
            "domain": domain,
        }
    except Exception as e:
        return {
            "status": "error",
            "scan_id": scan_id,
            "score": 0,
            "vulns": [str(e)],
            "risk_level": "ERROR",
            "duration": 0,
            "exit_code": 1,
            "domain": "",
            "error": str(e),
        }


def _generate_html(domain, score, vulns):
    score_class = "ok" if score > 70 else "warn" if score > 50 else "err"
    vulns_html = "".join(
        [f'<li class="err">&#10007; {v}</li>' for v in vulns]
    ) if vulns else '<li class="ok">&#10003; Sin problemas detectados</li>'

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>themperV1 Report - {domain}</title>
<style>
body{{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:20px;margin:0}}
h1{{color:#f85149;border-bottom:1px solid #30363d;padding-bottom:10px}}
h2{{color:#58a6ff;margin-top:0}}
.ok{{color:#3fb950}}.warn{{color:#d29922}}.err{{color:#f85149}}
.score{{font-size:48px;font-weight:bold;text-align:center;padding:20px 0}}
.box{{border:1px solid #30363d;padding:15px;margin:10px 0;border-radius:6px;background:#161b22}}
ul{{list-style:none;padding:0}}li{{padding:5px 0}}
.footer{{margin-top:30px;color:#8b949e;font-size:12px;text-align:center;border-top:1px solid #30363d;padding-top:15px}}
</style>
</head>
<body>
<h1>themperV1 v1.3 Security Report</h1>
<div class="box">
<h2>Target: {domain}</h2>
<p>Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p class="score {score_class}">Score: {max(0, score)}/100</p>
</div>
<div class="box">
<h2>Vulnerabilidades Detectadas: {len(vulns)}</h2>
<ul>{vulns_html}</ul>
</div>
<div class="footer">Generado por themperV1.3 FULL - SauNuz Team</div>
</body>
</html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=True, threaded=True)
