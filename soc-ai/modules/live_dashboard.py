import http.server,json,os,socketserver
from datetime import datetime

TRIAGE=os.path.expanduser("~/AI-SOC/soc-ai/logs/triage_log.jsonl")
INCIDENTS=os.path.expanduser("~/AI-SOC/soc-ai/logs/incidents.log")
SOAR=os.path.expanduser("~/AI-SOC/soc-ai/logs/soar_responses.jsonl")
PORT=8080

def load_triage():
    entries=[]
    try:
        with open(TRIAGE) as f:
            for l in f:
                try:
                    e=json.loads(l.strip())
                    if e.get("severity") and e.get("severity") not in ["?","name"]:
                        entries.append(e)
                except:pass
    except:pass
    return entries[-50:]

def load_soar():
    entries=[]
    try:
        with open(SOAR) as f:
            for l in f:
                try: entries.append(json.loads(l.strip()))
                except:pass
    except:pass
    return entries[-20:]

def build_html(entries,soar):
    from collections import Counter
    sevs=Counter(e.get("severity","?") for e in entries)
    atks=Counter(e.get("attack_type","?") for e in entries)
    sev_color={"Critical":"#A32D2D","High":"#BA7517","Medium":"#185FA5","Low":"#3B6D11"}
    rows=""
    for e in reversed(entries[-20:]):
        sev=e.get("severity","?")
        c=sev_color.get(sev,"#888")
        rows+=f"""<tr>
<td>{e.get("timestamp","")[:19]}</td>
<td><span style="color:{c};font-weight:500">{sev}</span></td>
<td>{e.get("attack_type","?")}</td>
<td>{e.get("rule_id","?")} (L{e.get("rule_level","?")})</td>
<td>{e.get("mitre_tactic","N/A")}</td>
<td>{e.get("false_positive_chance","?")}</td>
<td style="max-width:300px;font-size:11px">{e.get("recommended_action","N/A")}</td>
</tr>"""
    soar_rows=""
    for s in reversed(soar[-10:]):
        t=s.get("triage",{})
        acts=[r.get("action","?") for r in s.get("results",[])]
        soar_rows+=f"""<tr>
<td>{s.get("timestamp","")[:19]}</td>
<td>{s.get("playbook","?")}</td>
<td>{t.get("severity","?")}</td>
<td>{", ".join(acts)}</td>
</tr>"""
    crit=sevs.get("Critical",0)
    high=sevs.get("High",0)
    med=sevs.get("Medium",0)
    low=sevs.get("Low",0)
    top_atk=atks.most_common(1)[0][0] if atks else "None"
    now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="30">
<title>AI-SOC Dashboard — hax0023</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
h1{{font-size:1.4rem;color:#21e06a;margin-bottom:4px}}
.sub{{color:#8b949e;font-size:.85rem;margin-bottom:20px}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 16px}}
.card-label{{font-size:.75rem;color:#8b949e;margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em}}
.card-val{{font-size:1.8rem;font-weight:600}}
.crit{{color:#f85149}}.high{{color:#f0883e}}
.med{{color:#58a6ff}}.low{{color:#3fb950}}
.green{{color:#21e06a}}
table{{width:100%;border-collapse:collapse;font-size:.8rem;margin-bottom:20px}}
th{{background:#161b22;color:#8b949e;text-align:left;padding:8px 10px;border-bottom:2px solid #30363d;font-size:.72rem;text-transform:uppercase}}
td{{padding:7px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
tr:hover td{{background:#161b22}}
.section-title{{font-size:.95rem;font-weight:600;color:#e6edf3;margin:16px 0 8px;padding-bottom:6px;border-bottom:1px solid #30363d}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:600}}
.refresh{{color:#8b949e;font-size:.75rem;float:right}}
</style></head>
<body>
<h1>AI-SOC Live Dashboard — hax0023</h1>
<div class="sub">Auto-refreshes every 30s &nbsp;|&nbsp; Last updated: {now} <span class="refresh">Powered by Wazuh + Ollama LLaMA3.2</span></div>
<div class="cards">
<div class="card"><div class="card-label">Total AI analyses</div><div class="card-val green">{len(entries)}</div></div>
<div class="card"><div class="card-label">Critical alerts</div><div class="card-val crit">{crit}</div></div>
<div class="card"><div class="card-label">High alerts</div><div class="card-val high">{high}</div></div>
<div class="card"><div class="card-label">SOAR responses</div><div class="card-val med">{len(soar)}</div></div>
</div>
<div class="cards">
<div class="card"><div class="card-label">Medium alerts</div><div class="card-val med">{med}</div></div>
<div class="card"><div class="card-label">Low alerts</div><div class="card-val low">{low}</div></div>
<div class="card"><div class="card-label">Top attack type</div><div class="card-val" style="font-size:1rem;padding-top:6px;color:#e6edf3">{top_atk}</div></div>
<div class="card"><div class="card-label">Stack status</div><div class="card-val green" style="font-size:1rem;padding-top:6px">ONLINE</div></div>
</div>
<div class="section-title">Recent AI Triage — Last 20 alerts</div>
<table><tr><th>Time</th><th>Severity</th><th>Attack type</th><th>Rule</th><th>MITRE</th><th>False+</th><th>Recommended action</th></tr>
{rows}</table>
<div class="section-title">SOAR Automated Responses — Last 10</div>
<table><tr><th>Time</th><th>Playbook</th><th>Severity</th><th>Actions taken</th></tr>
{soar_rows}</table>
</body></html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        entries=load_triage()
        soar=load_soar()
        html=build_html(entries,soar)
        self.send_response(200)
        self.send_header("Content-type","text/html")
        self.end_headers()
        self.wfile.write(html.encode())

print(f"[*] SOC Dashboard running at http://localhost:{PORT}")
print("[*] Auto-refreshes every 30s — Ctrl+C to stop")
with socketserver.TCPServer(("",PORT),Handler) as s:
    s.serve_forever()
