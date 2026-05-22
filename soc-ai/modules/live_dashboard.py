import http.server,json,os,socketserver,urllib.request,subprocess
from datetime import datetime
from collections import Counter
TRIAGE=os.path.expanduser("~/AI-SOC/soc-ai/logs/triage_log.jsonl")
SOAR=os.path.expanduser("~/AI-SOC/soc-ai/logs/soar_responses.jsonl")
BLOCKED=os.path.expanduser("~/AI-SOC/soc-ai/logs/blocked_ips.json")
PORT=8080

def fmt_ts(ts):
    try:
        dt=datetime.fromisoformat(ts[:19]);d=dt.day
        sfx="th" if 11<=d<=13 else {1:"st",2:"nd",3:"rd"}.get(d%10,"th")
        return dt.strftime(f"{d}{sfx} %B %Y, %H:%M:%S")
    except: return ts[:19]

def sc(s):
    return {"Critical":"#f85149","High":"#f0883e","Medium":"#58a6ff","Low":"#3fb950"}.get(s,"#8b949e")

def load_triage():
    SKIP=["19007","19004","19008","19009","19010"]
    out=[]
    try:
        with open(TRIAGE) as f:
            for l in f:
                try:
                    e=json.loads(l.strip())
                    if e.get("rule_id","") not in SKIP: out.append(e)
                except: pass
    except: pass
    return out

def load_soar():
    out=[]
    try:
        with open(SOAR) as f:
            for l in f:
                try: out.append(json.loads(l.strip()))
                except: pass
    except: pass
    return out

def load_blocked():
    try:
        with open(BLOCKED) as f: return json.load(f)
    except: return []

CSS="""<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}
nav{display:flex;align-items:center;gap:24px;padding:14px 28px;background:#161b22;border-bottom:1px solid #30363d;position:sticky;top:0;z-index:100}
nav .brand{font-weight:700;font-size:1.1rem;color:#21e06a;text-decoration:none;margin-right:auto}
nav a{color:#8b949e;text-decoration:none;font-size:.875rem;padding:5px 10px;border-radius:6px;transition:.15s}
nav a:hover,nav a.active{color:#e6edf3;background:#21262d}
.page{padding:28px;max-width:1400px;margin:0 auto}
h1{font-size:1.25rem;color:#e6edf3;margin-bottom:4px}
.sub{color:#8b949e;font-size:.8rem;margin-bottom:20px}
.health{display:flex;gap:10px;margin-bottom:24px;flex-wrap:wrap}
.hitem{display:flex;align-items:center;gap:7px;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:7px 14px;font-size:.8rem}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.on{background:#21e06a;box-shadow:0 0 6px #21e06a88}
.off{background:#f85149}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:28px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px 18px}
.card-label{font-size:.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.card-val{font-size:2rem;font-weight:700}
.ct{color:#21e06a}.cc{color:#f85149}.ch{color:#f0883e}.cm{color:#58a6ff}.cl{color:#3fb950}
.section{font-size:.9rem;font-weight:600;color:#e6edf3;margin:0 0 10px;padding-bottom:8px;border-bottom:1px solid #21262d;display:flex;justify-content:space-between;align-items:center}
.section a{font-size:.75rem;color:#58a6ff;text-decoration:none}
.section a:hover{text-decoration:underline}
table{width:100%;border-collapse:collapse;font-size:.8rem;margin-bottom:32px}
th{background:#161b22;color:#6e7681;text-align:left;padding:9px 12px;border-bottom:2px solid #30363d;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em}
td{padding:9px 12px;border-bottom:1px solid #21262d;vertical-align:top}
tr:hover td{background:#161b22}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.7rem;font-weight:600;color:#0d1117}
.fp{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;background:#21262d;color:#8b949e}
.pill{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;background:#21262d;color:#58a6ff;margin:1px}
.act{max-width:280px;font-size:.75rem;color:#8b949e;line-height:1.5}
.empty{color:#8b949e;font-size:.85rem;padding:20px 12px;text-align:center}
</style>"""

NAV="""<nav>
  <a href="/" class="brand">AI-SOC</a>
  <a href="/" id="n-home">Dashboard</a>
  <a href="/complete-logs" id="n-logs">Complete Logs</a>
  <a href="/blocked" id="n-blocked">Blocked IPs</a>
</nav>"""

def anav(html,pid):
    return html.replace(f'id="{pid}"',f'id="{pid}" class="active"')

def health_bar(entries,soar):
    def wazuh_ok():
        try: return "wazuh.manager" in subprocess.run(["docker","ps","--format","{{.Names}}"],capture_output=True,text=True).stdout
        except: return False
    def ollama_ok():
        try: urllib.request.urlopen("http://localhost:11434/api/tags",timeout=2); return True
        except: return False
    checks=[("Wazuh",wazuh_ok()),("Ollama LLM",ollama_ok()),("SOAR Engine",len(soar)>0)]
    last=fmt_ts(entries[-1]["timestamp"]) if entries else "No data yet"
    h='<div class="health">'
    for name,ok in checks:
        dot="on" if ok else "off"
        st="Online" if ok else "Offline"
        h+=f'<div class="hitem"><span class="dot {dot}"></span>{name}: <strong>{st}</strong></div>'
    h+=f'<div class="hitem"><span class="dot on"></span>Last event: <strong>{last}</strong></div>'
    return h+"</div>"

def build_home(entries,soar,blocked):
    sevs=Counter(e.get("severity","Unknown") for e in entries)
    ips=set()
    for e in entries:
        ip=e.get("srcip") or e.get("data",{}).get("srcip","")
        if ip and ip not in ("N/A",""): ips.add(ip)
    now=fmt_ts(datetime.now().isoformat())
    recent=[e for e in reversed(entries) if e.get("severity") not in (None,"?","Unknown","None")][:10]
    rows=""
    for e in recent:
        sev=e.get("severity","?");c=sc(sev)
        atk=e.get("attack_type") or e.get("original_description","Unknown")
        mitre=e.get("mitre_tactic","N/A");fp=e.get("false_positive_chance","?")
        act=e.get("recommended_action","\u2014");ts=fmt_ts(e.get("timestamp",""))
        rows+=f'<tr><td>{ts}</td><td><span class="badge" style="background:{c}">{sev}</span></td><td>{atk}</td><td>{mitre}</td><td><span class="fp">{fp}</span></td><td class="act">{act}</td></tr>'
    soar_rows=""
    for s in list(reversed(soar))[:5]:
        t=s.get("triage",{});acts=[r.get("action","?") for r in s.get("results",[])]
        sev=t.get("severity","?");c=sc(sev);pb=s.get("playbook","?");ts=fmt_ts(s.get("timestamp",""))
        pills="".join(f'<span class="pill">{a}</span>' for a in acts)
        soar_rows+=f'<tr><td>{ts}</td><td>{pb}</td><td><span class="badge" style="background:{c}">{sev}</span></td><td>{pills}</td></tr>'
    nt='<tr><td colspan="6" class="empty">No triaged alerts yet</td></tr>'
    ns='<tr><td colspan="4" class="empty">No SOAR responses yet</td></tr>'
    html=f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="30"><title>AI-SOC</title>{CSS}</head><body>{NAV}
<div class="page">
<h1>Security Operations Center</h1>
<div class="sub">Auto-refreshes every 30s &nbsp;&middot;&nbsp; {now} &nbsp;&middot;&nbsp; Wazuh + LLaMA3.2 (local)</div>
{health_bar(entries,soar)}
<div class="cards">
<div class="card"><div class="card-label">Unique Source IPs</div><div class="card-val ct">{len(ips)}</div></div>
<div class="card"><div class="card-label">Critical</div><div class="card-val cc">{sevs.get("Critical",0)}</div></div>
<div class="card"><div class="card-label">High</div><div class="card-val ch">{sevs.get("High",0)}</div></div>
<div class="card"><div class="card-label">Medium</div><div class="card-val cm">{sevs.get("Medium",0)}</div></div>
<div class="card"><div class="card-label">Low</div><div class="card-val cl">{sevs.get("Low",0)}</div></div>
</div>
<div class="section"><span>Recent Triage &mdash; Last 10 Alerts</span><a href="/complete-logs">View all &rarr;</a></div>
<table><tr><th>Time</th><th>Severity</th><th>Attack</th><th>MITRE</th><th>False Positive</th><th>Recommended Action</th></tr>
{rows or nt}</table>
<div class="section"><span>SOAR Automated Responses &mdash; Last 5</span><a href="/complete-logs">View all &rarr;</a></div>
<table><tr><th>Time</th><th>Playbook</th><th>Severity</th><th>Actions Taken</th></tr>
{soar_rows or ns}</table>
</div></body></html>"""
    return anav(html,"n-home")

def build_logs(entries):
    now=fmt_ts(datetime.now().isoformat());rows=""
    for e in reversed(entries):
        sev=e.get("severity","Unknown");c=sc(sev)
        atk=e.get("attack_type") or e.get("original_description","Unknown")
        agent=e.get("agent","?");mitre=e.get("mitre_tactic","N/A")
        fp=e.get("false_positive_chance","?");act=e.get("recommended_action","\u2014")
        ts=fmt_ts(e.get("timestamp",""))
        rows+=f'<tr><td>{ts}</td><td><span class="badge" style="background:{c}">{sev}</span></td><td>{atk}</td><td>{agent}</td><td>{mitre}</td><td><span class="fp">{fp}</span></td><td class="act">{act}</td></tr>'
    no='<tr><td colspan="7" class="empty">No logs yet</td></tr>'
    html=f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>AI-SOC &mdash; Logs</title>{CSS}</head><body>{NAV}
<div class="page"><h1>Complete Alert Logs</h1>
<div class="sub">All {len(entries)} triaged events &nbsp;&middot;&nbsp; {now}</div>
<table><tr><th>Time</th><th>Severity</th><th>Attack</th><th>Agent</th><th>MITRE</th><th>False Positive</th><th>Recommended Action</th></tr>
{rows or no}</table></div></body></html>"""
    return anav(html,"n-logs")

def build_blocked(blocked):
    now=fmt_ts(datetime.now().isoformat())
    rows="".join(f'<tr><td>{ip}</td><td><span class="badge" style="background:#f85149">Blocked</span></td><td>Auto-block via SOAR playbook</td></tr>' for ip in blocked)
    no='<tr><td colspan="3" class="empty">No IPs blocked yet</td></tr>'
    html=f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>AI-SOC &mdash; Blocked IPs</title>{CSS}</head><body>{NAV}
<div class="page"><h1>Blocked IP Addresses</h1>
<div class="sub">{len(blocked)} IP(s) currently blocked &nbsp;&middot;&nbsp; {now}</div>
<table><tr><th>IP Address</th><th>Status</th><th>Reason</th></tr>
{rows or no}</table></div></body></html>"""
    return anav(html,"n-blocked")

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        entries=load_triage();soar=load_soar();blocked=load_blocked()
        path=self.path.split("?")[0]
        if path=="/": html=build_home(entries,soar,blocked)
        elif path=="/complete-logs": html=build_logs(entries)
        elif path=="/blocked": html=build_blocked(blocked)
        else: self.send_response(404);self.end_headers();return
        self.send_response(200);self.send_header("Content-type","text/html");self.end_headers()
        self.wfile.write(html.encode())

print(f"[*] AI-SOC Dashboard  -> http://localhost:{PORT}")
print(f"[*] Complete Logs     -> http://localhost:{PORT}/complete-logs")
print(f"[*] Blocked IPs       -> http://localhost:{PORT}/blocked")
print("[*] Auto-refreshes every 30s | Ctrl+C to stop\n")
with socketserver.TCPServer(("",PORT),Handler) as s: s.serve_forever()
