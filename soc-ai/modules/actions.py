import subprocess,json,os
from datetime import datetime

INCIDENT_LOG=os.path.expanduser("~/AI-SOC/soc-ai/logs/incidents.log")
BLOCKED_IPS=os.path.expanduser("~/AI-SOC/soc-ai/logs/blocked_ips.json")
os.makedirs(os.path.dirname(INCIDENT_LOG),exist_ok=True)

def get_blocked():
    try:
        with open(BLOCKED_IPS) as f: return json.load(f)
    except: return []

def save_blocked(ips):
    with open(BLOCKED_IPS,"w") as f: json.dump(ips,f)

def block_ip(ip,reason="SOC auto-block"):
    if not ip or ip in ["127.0.0.1","N/A","?"]: 
        return {"status":"skipped","reason":"localhost or invalid IP"}
    blocked=get_blocked()
    if ip in blocked:
        return {"status":"already_blocked","ip":ip}
    try:
        subprocess.run(
            ["sudo","iptables","-I","INPUT","-s",ip,"-j","DROP"],
            capture_output=True,text=True,timeout=10)
        blocked.append(ip)
        save_blocked(blocked)
        log_incident(f"BLOCKED IP {ip} — {reason}")
        return {"status":"blocked","ip":ip}
    except Exception as e:
        return {"status":"error","error":str(e)}

def unblock_ip(ip):
    try:
        subprocess.run(
            ["sudo","iptables","-D","INPUT","-s",ip,"-j","DROP"],
            capture_output=True,text=True,timeout=10)
        blocked=get_blocked()
        if ip in blocked: blocked.remove(ip)
        save_blocked(blocked)
        return {"status":"unblocked","ip":ip}
    except Exception as e:
        return {"status":"error","error":str(e)}

def log_incident(msg,triage=None):
    ts=datetime.now().isoformat()
    with open(INCIDENT_LOG,"a") as f:
        f.write(f"[{ts}] {msg}\n")
        if triage:
            f.write(f"  Severity : {triage.get('severity')}\n")
            f.write(f"  Attack   : {triage.get('attack_type')}\n")
            f.write(f"  MITRE    : {triage.get('mitre_tactic')}\n")
            f.write(f"  Action   : {triage.get('recommended_action')}\n")
            f.write(f"  Summary  : {triage.get('explanation')}\n\n")

def console_alert(triage):
    RED="\033[91m";YEL="\033[93m";R="\033[0m";BLD="\033[1m"
    sev=triage.get("severity","?")
    c=RED if sev=="Critical" else YEL
    print(f"\n{BLD}{'!'*55}{R}")
    print(f"{c}{BLD}  SOAR AUTO-RESPONSE TRIGGERED{R}")
    print(f"  Severity : {c}{sev}{R}")
    print(f"  Attack   : {triage.get('attack_type')}")
    print(f"  Rule     : {triage.get('rule_id')}")
    print(f"  Action   : {triage.get('recommended_action')}")
    print(f"{'!'*55}\n")
