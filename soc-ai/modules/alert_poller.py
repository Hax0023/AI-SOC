import subprocess,json,os,sys,time
from datetime import datetime
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from ai_triage import analyze_alert,log_triage,print_triage

POLL=30
MIN_LEVEL=6
SEEN=os.path.expanduser('~/AI-SOC/soc-ai/logs/seen.json')
os.makedirs(os.path.dirname(SEEN),exist_ok=True)

def load_seen():
    try:
        with open(SEEN) as f: return set(json.load(f))
    except: return set()

def save_seen(s):
    with open(SEEN,'w') as f:
        json.dump(list(s)[-500:],f)

def get_alerts(seen):
    r=subprocess.run(
        ['docker','exec','single-node-wazuh.manager-1',
         'tail','-80','/var/ossec/logs/alerts/alerts.json'],
        capture_output=True,text=True)
    new=[]
    for line in r.stdout.splitlines():
        try:
            a=json.loads(line.strip())
            rule=a.get('rule',{})
            lvl=int(rule.get('level',0))
            uid=a.get('timestamp','')+'-'+rule.get('id','')
            if uid not in seen and lvl>=MIN_LEVEL:
                new.append((uid,a))
        except:pass
    return new

def run():
    print('SOC AI TRIAGE POLLER - Ollama LLaMA3')
    print(f'Polling {POLL}s | Min level: {MIN_LEVEL}')
    seen=load_seen()
    total=0
    while True:
        try:
            ts=datetime.now().strftime('%H:%M:%S')
            new=get_alerts(seen)
            if new:
                print(f'[{ts}] {len(new)} new alert(s) -- analyzing...')
                for uid,alert in new:
                    rule=alert.get('rule',{})
                    lvl=rule.get('level','?')
                    desc=rule.get('description','?')[:40]
                    print(f'  >> [Level {lvl}] {desc}...')
                    res=analyze_alert(alert)
                    print_triage(res)
                    log_triage(res)
                    seen.add(uid)
                    total+=1
                save_seen(seen)
            else:
                print(f'[{ts}] No new alerts. Total analyzed: {total}')
            time.sleep(POLL)
        except KeyboardInterrupt:
            print(f'\n[*] Poller stopped. Total analyzed: {total}')
            break
        except Exception as e:
            print(f'[!] Error: {e}')
            time.sleep(10)

if __name__=='__main__':
    run()
