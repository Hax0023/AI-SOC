import json,os,sys,time,yaml
from datetime import datetime
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from ai_triage import analyze_alert,log_triage
from actions import block_ip,log_incident,console_alert

PLAYBOOK_DIR=os.path.expanduser("~/AI-SOC/soc-ai/playbooks")
SEEN=os.path.expanduser("~/AI-SOC/soc-ai/logs/soar_seen.json")
RESPONSE_LOG=os.path.expanduser("~/AI-SOC/soc-ai/logs/soar_responses.jsonl")
os.makedirs(os.path.dirname(SEEN),exist_ok=True)

def load_playbooks():
    books=[]
    for f in os.listdir(PLAYBOOK_DIR):
        if f.endswith(".yml"):
            with open(os.path.join(PLAYBOOK_DIR,f)) as fh:
                books.append(yaml.safe_load(fh))
    return books

def match_playbook(triage,playbooks):
    sev_rank={"Low":1,"Medium":2,"High":3,"Critical":4}
    for pb in playbooks:
        t=pb.get("trigger",{})
        atk=t.get("attack_type","").lower()
        min_sev=t.get("min_severity","High")
        triage_atk=triage.get("attack_type","").lower()
        if atk in triage_atk or triage_atk in atk or any(w in triage_atk for w in atk.split()):
            if sev_rank.get(triage.get("severity","Low"),1)>=sev_rank.get(min_sev,1):
                return pb

def get_src_ip(alert):
    d=alert.get("data",{})
    for k in ["srcip","src_ip","data.srcip"]:
        if d.get(k): return d.get(k)
    return alert.get("data",{}).get("srcip","N/A")

def run_playbook(pb,triage,alert):
    results=[]
    ip=get_src_ip(alert)
    for action in pb.get("actions",[]):
        if not action.get("enabled"): continue
        atype=action.get("type")
        if atype=="firewall_block":
            r=block_ip(ip,triage.get("attack_type","SOC"))
            results.append({"action":"block_ip","result":r})
        elif atype=="log_incident":
            log_incident(f"INCIDENT: {triage.get('attack_type')} from {ip}",triage)
            results.append({"action":"log_incident","result":"logged"})
        elif atype=="console_alert":
            console_alert(triage)
            results.append({"action":"console_alert","result":"displayed"})
    entry={"timestamp":datetime.now().isoformat(),
           "playbook":pb.get("name"),
           "triage":triage,"results":results}
    with open(RESPONSE_LOG,"a") as f:
        f.write(json.dumps(entry)+"\n")
    return results

def load_seen():
    try:
        with open(SEEN) as f: return set(json.load(f))
    except: return set()

def save_seen(s):
    with open(SEEN,"w") as f: json.dump(list(s)[-500:],f)

def get_alerts(seen):
    import subprocess
    r=subprocess.run(
        ["docker","exec","single-node-wazuh.manager-1",
         "tail","-50","/var/ossec/logs/alerts/alerts.json"],
        capture_output=True,text=True)
    new=[]
    for line in r.stdout.splitlines():
        try:
            a=json.loads(line.strip())
            rule=a.get("rule",{})
            lvl=int(rule.get("level",0))
            uid=a.get("timestamp","")+"-"+rule.get("id","")
            if uid not in seen and lvl>=6:
                new.append((uid,a))
        except:pass
    return new

def run():
    print("="*55)
    print("  SOAR ENGINE — AI-Assisted Auto Response")
    print("  Polling every 30s | Min alert level: 8")
    print("="*55+"\n")
    playbooks=load_playbooks()
    print(f"[*] Loaded {len(playbooks)} playbook(s)")
    for pb in playbooks:
        print(f"    - {pb.get('name')}")
    print()
    seen=load_seen()
    total_responses=0
    while True:
        try:
            ts=datetime.now().strftime("%H:%M:%S")
            new=get_alerts(seen)
            if new:
                print(f"[{ts}] {len(new)} new alert(s) found")
                for uid,alert in new:
                    rule=alert.get("rule",{})
                    print(f"  >> Analyzing: [{rule.get('level')}] {rule.get('description','')[:40]}...")
                    triage=analyze_alert(alert)
                    log_triage(triage)
                    pb=match_playbook(triage,playbooks)
                    if pb:
                        print(f"  >> Matched playbook: {pb.get('name')}")
                        results=run_playbook(pb,triage,alert)
                        print(f"  >> Actions taken: {[r['action'] for r in results]}")
                        total_responses+=1
                    else:
                        print(f"  >> No playbook matched — logged only")
                    seen.add(uid)
                save_seen(seen)
            else:
                print(f"[{ts}] No new alerts. Responses so far: {total_responses}")
            time.sleep(30)
        except KeyboardInterrupt:
            print(f"\n[*] SOAR stopped. Total responses: {total_responses}")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(10)

if __name__=="__main__":
    run()
