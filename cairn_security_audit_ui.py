#!/usr/bin/env python3
"""Local browser UI for CAIRN Security Agent Audit.

This is a localhost-only wrapper around the existing CLI pipeline. It does not
upload logs anywhere, execute pentest actions, or serve cached outputs.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parent
PILOT = ROOT / "pilot"
if str(PILOT) not in sys.path:
    sys.path.insert(0, str(PILOT))

import cairn_audit_agent_logs as audit
import ingest_agent_trace  # type: ignore
from cairn_pilot_from_raw_logs import events_from_records, write_normalized_trace


DEFAULT_OUT = ROOT / "report"


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def run_audit(
    input_path: Path,
    out_path: Path,
    price_input_per_m: float,
    glob_pattern: str | None,
    no_cleaned_trace: bool,
    max_rows: int,
    max_records: int,
) -> dict[str, Any]:
    loaded: list[tuple[Path, dict[str, Any]]] = []
    for path, obj in ingest_agent_trace.iter_input(input_path, glob_pattern):
        loaded.append((path, obj))
        if max_rows and len(loaded) >= max_rows:
            break

    ingest_args = SimpleNamespace(readonly_cache_only=False, max_records=max_records)
    records, ingest_stats = ingest_agent_trace.convert_objects(loaded, "auto", ingest_args)

    out_path.mkdir(parents=True, exist_ok=True)
    normalized_path = out_path / "cleaned_trace.jsonl"
    if no_cleaned_trace:
        events = events_from_records(records)
    else:
        write_normalized_trace(records, normalized_path, keep_output_text=True)
        events = audit.load_events(normalized_path)

    result = audit.analyze(events, price_input_per_m)
    result["normalization"] = {
        **ingest_stats,
        "cleaned_trace": "" if no_cleaned_trace else str(normalized_path),
        "output_text_retained": True,
        "cleaned_trace_written": not no_cleaned_trace,
    }
    audit.write_json(out_path / "summary.json", result)
    audit.write_markdown(out_path / "summary.md", result, input_path)
    audit.write_html(out_path / "report.html", result, input_path)
    (out_path / "normalization_summary.json").write_text(
        json.dumps(result["normalization"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def fmt_int(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except Exception:
        return "0"


def fmt_pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.2f}%"
    except Exception:
        return "0.00%"


def html_page() -> str:
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CAIRN Security Agent Audit</title>
<style>
:root {
  --bg:#070a12; --panel:#0f1422; --panel2:#121a2b; --line:#243047;
  --text:#e8edf7; --muted:#8e9ab2; --accent:#8b7fff; --accent2:#45d6a0;
  --warn:#f0b85a; --bad:#ff7f8f;
}
* { box-sizing:border-box; }
body {
  margin:0; color:var(--text); background:
    radial-gradient(circle at 15% 8%, rgba(139,127,255,.18), transparent 28rem),
    radial-gradient(circle at 90% 20%, rgba(69,214,160,.11), transparent 30rem),
    var(--bg);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height:1.5;
}
.wrap { max-width:1120px; margin:0 auto; padding:34px 20px 56px; }
.top { display:flex; justify-content:space-between; gap:22px; align-items:flex-start; margin-bottom:28px; }
.brand { display:flex; gap:14px; align-items:center; }
.logo { width:54px; height:54px; object-fit:contain; filter:drop-shadow(0 10px 26px rgba(139,127,255,.2)); }
.eyebrow { color:var(--accent); font-size:12px; letter-spacing:.14em; text-transform:uppercase; font-weight:700; }
h1 { margin:4px 0 6px; font-size:34px; letter-spacing:-.03em; line-height:1.05; }
.sub { color:var(--muted); max-width:730px; margin:0; font-size:16px; }
.scope { color:var(--muted); border:1px solid var(--line); background:rgba(15,20,34,.72); border-radius:8px; padding:12px 14px; max-width:390px; font-size:13px; }
.grid { display:grid; grid-template-columns: .92fr 1.08fr; gap:18px; }
.card { background:rgba(15,20,34,.86); border:1px solid var(--line); border-radius:10px; padding:18px; box-shadow:0 18px 50px rgba(0,0,0,.22); }
.card h2 { margin:0 0 12px; font-size:18px; letter-spacing:-.01em; }
label { display:block; color:#c9d1e5; font-size:13px; font-weight:650; margin:14px 0 6px; }
input[type=text], input[type=number] {
  width:100%; border:1px solid #2b3854; background:#090d18; color:var(--text);
  border-radius:8px; padding:11px 12px; font-size:14px; outline:none;
}
input:focus { border-color:var(--accent); box-shadow:0 0 0 3px rgba(139,127,255,.14); }
.row { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
.check { display:flex; align-items:center; gap:9px; margin-top:14px; color:var(--muted); font-size:13px; }
button {
  margin-top:18px; width:100%; border:0; border-radius:8px; padding:12px 14px;
  background:linear-gradient(135deg, var(--accent), #6b5cff); color:white;
  font-weight:750; letter-spacing:.02em; cursor:pointer; font-size:14px;
}
button:disabled { opacity:.55; cursor:wait; }
.hint { color:var(--muted); font-size:12px; margin-top:10px; }
.quick { display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }
.quick button { width:auto; margin:0; padding:8px 10px; background:#172037; border:1px solid #2b3854; font-size:12px; color:#cbd5ea; }
.metrics { display:grid; grid-template-columns:repeat(3, 1fr); gap:10px; margin-bottom:14px; }
.metric { background:var(--panel2); border:1px solid var(--line); border-radius:8px; padding:12px; min-height:82px; }
.metric .label { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em; }
.metric .value { margin-top:6px; font-size:24px; font-weight:800; letter-spacing:-.03em; }
.metric.good .value { color:var(--accent2); }
.metric.warn .value { color:var(--warn); }
.metric.bad .value { color:var(--bad); }
.empty { color:var(--muted); padding:30px 10px; text-align:center; border:1px dashed #2b3854; border-radius:8px; background:#0a0e19; }
.links { display:flex; flex-wrap:wrap; gap:8px; margin:12px 0 16px; }
.links a { color:white; text-decoration:none; background:#172037; border:1px solid #2b3854; border-radius:7px; padding:8px 10px; font-size:13px; }
table { width:100%; border-collapse:collapse; font-size:13px; overflow:hidden; border-radius:8px; }
th, td { text-align:left; padding:9px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em; }
td:last-child, th:last-child { text-align:right; }
.examples { margin-top:14px; }
.example { border:1px solid var(--line); background:#0a0e19; border-radius:8px; padding:10px; margin-top:8px; }
.example b { color:var(--accent2); }
code { color:#d8dcff; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; }
.error { color:#ffd8dc; background:rgba(255,127,143,.12); border:1px solid rgba(255,127,143,.35); border-radius:8px; padding:12px; white-space:pre-wrap; }
.footer { margin-top:18px; color:var(--muted); font-size:12px; }
@media (max-width: 860px) {
  .top, .grid { display:block; }
  .scope { margin-top:16px; max-width:none; }
  .metrics { grid-template-columns:1fr 1fr; }
}
@media (max-width: 560px) { .metrics, .row { grid-template-columns:1fr; } h1 { font-size:27px; } }
</style>
</head>
<body>
<main class="wrap">
  <header class="top">
    <div>
      <div class="brand">
        <img class="logo" src="/asset/logo.png" alt="fraQtl">
        <div>
          <div class="eyebrow">Local audit for AI-pentest traces</div>
          <h1>CAIRN Security Agent Audit</h1>
        </div>
      </div>
      <p class="sub">Find repeated tool-output work, stale replay risk, protected-lane blocks, and token-savings opportunities from existing JSON/JSONL security-agent logs.</p>
    </div>
    <div class="scope"><strong>Demo/evaluation scope.</strong> This UI runs locally and wraps the audit CLI. It does not run pentests, use live target access, or auto-serve cached outputs.</div>
  </header>
  <section class="grid">
    <div class="card">
      <h2>Run Audit</h2>
      <label for="inputPath">Input file or folder</label>
      <input id="inputPath" type="text" value="samples/pentest_trace_sample.jsonl">
      <div class="quick">
        <button type="button" onclick="setSample()">Use sample trace</button>
        <button type="button" onclick="setExample()">View AutoPenBench report</button>
      </div>
      <label for="outPath">Output folder</label>
      <input id="outPath" type="text" value="report">
      <div class="row">
        <div>
          <label for="price">Input price / 1M tokens</label>
          <input id="price" type="number" min="0" step="0.01" value="3.0">
        </div>
        <div>
          <label for="glob">Folder glob</label>
          <input id="glob" type="text" placeholder="*.json">
        </div>
      </div>
      <label class="check"><input id="noCleaned" type="checkbox" checked> Do not persist cleaned trace</label>
      <button id="runButton" type="button" onclick="runAudit()">Run local audit</button>
      <p class="hint">Logs are read from local paths by this localhost process. Nothing is uploaded.</p>
    </div>
    <div class="card">
      <h2>Results</h2>
      <div id="result"><div class="empty">Run the sample or point CAIRN at a local JSON/JSONL trace.</div></div>
    </div>
  </section>
  <p class="footer">Product path: offline audit -> local dashboard -> protected runtime sidecar around one high-volume tool family.</p>
</main>
<script>
function setSample() {
  document.getElementById('inputPath').value = 'samples/pentest_trace_sample.jsonl';
  document.getElementById('outPath').value = 'report';
}
function setExample() {
  window.open('/file?path=examples/autopenbench/report.html', '_blank');
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtInt(v) { return Number(v || 0).toLocaleString(); }
function fmtPct(v) { return ((Number(v || 0)) * 100).toFixed(2) + '%'; }
function metric(label, value, cls='') {
  return `<div class="metric ${cls}"><div class="label">${label}</div><div class="value">${value}</div></div>`;
}
function render(data) {
  const s = data.summary || {};
  const out = esc(data.output_dir || 'report');
  const families = (data.top_families || []).slice(0, 8);
  const examples = (data.examples || []).slice(0, 5);
  let html = '<div class="metrics">';
  html += metric('Events audited', fmtInt(s.events));
  html += metric('Re-reads', fmtInt(s.re_reads), 'good');
  html += metric('Repeated work', fmtPct(s.repeated_work_percent / 100), 'good');
  html += metric('Point tokens avoided', fmtInt(s.point_tokens_avoided), 'good');
  html += metric('Protected blocks', fmtInt(s.protected_lane_blocks), 'warn');
  html += metric('Stale serves', fmtInt(s.stale_serves), s.stale_serves ? 'bad' : 'good');
  html += '</div>';
  html += `<div class="links">
    <a target="_blank" href="/file?path=${encodeURIComponent(out + '/report.html')}">Open report.html</a>
    <a target="_blank" href="/file?path=${encodeURIComponent(out + '/summary.md')}">Open summary.md</a>
    <a target="_blank" href="/file?path=${encodeURIComponent(out + '/summary.json')}">Open summary.json</a>
  </div>`;
  if (families.length) {
    html += '<table><thead><tr><th>Family</th><th>Re-reads</th><th>Carried avoided</th></tr></thead><tbody>';
    for (const row of families) {
      html += `<tr><td><code>${esc(row.family)}</code></td><td>${fmtInt(row.re_reads)}</td><td>${fmtInt(row.cumulative_carried_context_tokens_avoided)}</td></tr>`;
    }
    html += '</tbody></table>';
  }
  if (examples.length) {
    html += '<div class="examples"><h2>Examples</h2>';
    for (const ex of examples) {
      html += `<div class="example"><b>${esc(ex.action)} ${esc(ex.family)}</b> saved ${fmtInt(ex.point_tokens_avoided)} tokens<br><code>${esc(ex.command_text)}</code></div>`;
    }
    html += '</div>';
  }
  document.getElementById('result').innerHTML = html;
}
async function runAudit() {
  const btn = document.getElementById('runButton');
  btn.disabled = true;
  btn.textContent = 'Running...';
  document.getElementById('result').innerHTML = '<div class="empty">Running local audit...</div>';
  try {
    const res = await fetch('/api/run', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        input_path: document.getElementById('inputPath').value,
        out_path: document.getElementById('outPath').value,
        price_input_per_m: Number(document.getElementById('price').value || 0),
        glob: document.getElementById('glob').value,
        no_cleaned_trace: document.getElementById('noCleaned').checked
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Audit failed');
    render(data);
  } catch (err) {
    document.getElementById('result').innerHTML = `<div class="error">${esc(err.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run local audit';
  }
}
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "CAIRNAuditUI/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def send_text(self, status: int, text: str, content_type: str = "text/html; charset=utf-8") -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        self.send_text(status, json.dumps(payload, indent=2), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self.send_text(200, html_page())
            return
        if parsed.path == "/asset/logo.png":
            self.serve_file(ROOT / "docs" / "logo.png")
            return
        if parsed.path == "/file":
            params = urllib.parse.parse_qs(parsed.query)
            rel = params.get("path", [""])[0]
            self.serve_file((ROOT / rel).resolve(), require_root=True)
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/api/run":
            self.send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            input_path = Path(str(payload.get("input_path", ""))).expanduser()
            out_path = Path(str(payload.get("out_path", "report"))).expanduser()
            if not input_path.is_absolute():
                input_path = ROOT / input_path
            if not out_path.is_absolute():
                out_path = ROOT / out_path
            if not input_path.exists():
                raise ValueError(f"Input path does not exist: {input_path}")
            result = run_audit(
                input_path=input_path,
                out_path=out_path,
                price_input_per_m=float(payload.get("price_input_per_m", 0.0) or 0.0),
                glob_pattern=str(payload.get("glob") or "") or None,
                no_cleaned_trace=bool(payload.get("no_cleaned_trace", True)),
                max_rows=int(payload.get("max_rows", 0) or 0),
                max_records=int(payload.get("max_records", 0) or 0),
            )
            self.send_json(
                200,
                {
                    "summary": result.get("summary", {}),
                    "top_families": result.get("top_repeated_families", []),
                    "examples": result.get("top_examples", []),
                    "normalization": result.get("normalization", {}),
                    "output_dir": display_path(out_path),
                },
            )
        except Exception as exc:
            self.send_json(400, {"error": str(exc)})

    def serve_file(self, path: Path, require_root: bool = False) -> None:
        try:
            resolved = path.resolve()
            if require_root and ROOT not in (resolved, *resolved.parents):
                self.send_json(403, {"error": "path outside repository"})
                return
            if not resolved.exists() or not resolved.is_file():
                self.send_json(404, {"error": f"file not found: {resolved}"})
                return
            content_type = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
            data = resolved.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local CAIRN Security Agent Audit UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--no-open", action="store_true", help="Do not open a browser automatically.")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"CAIRN Security Agent Audit UI -> {url}")
    print("Press Ctrl-C to stop.")
    if not args.no_open:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
