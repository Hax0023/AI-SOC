import json,os
from collections import Counter
from datetime import datetime

LOG=os.path.expanduser('~/AI-SOC/soc-ai/logs/triage_log.jsonl')

def load_entries():
    entries=[]
    try:
        with open(LOG) as f:
            for l in f:
                try:
                    e=json.loads(l.strip())
                    if e.get('severity') and e.get('severity') not in ['?','name']:
                        entries.append(e)
                except:pass
    except:pass
    return entries

def print_report(entries):
    RED='\033[91m';YEL='\033[93m';BLU='\033[94m';GRN='\033[92m'
    CYN='\033[96m';BLD='\033[1m';R='\033[0m'
    W=60
    print('\n'+BLD+CYN+'='*W+R)
    print(BLD+CYN+'  AI-SOC TRIAGE REPORT — hax0023'+R)
    print(BLD+CYN+'  '+datetime.now().strftime('%Y-%m-%d %H:%M:%S')+R)
    print(BLD+CYN+'='*W+R)
    total=len(entries)
    sevs=Counter(e.get('severity','?') for e in entries)
    atks=Counter(e.get('attack_type','?') for e in entries)
    mitres=Counter(e.get('mitre_tactic','?') for e in entries)
    fps=Counter(e.get('false_positive_chance','?') for e in entries)
    print(f'\n{BLD}  SUMMARY{R}')
    print(f'  Total AI Analyses : {BLD}{total}{R}')
    print(f'  Critical Alerts   : {RED}{sevs.get("Critical",0)}{R}')
    print(f'  High Alerts       : {YEL}{sevs.get("High",0)}{R}')
    print(f'  Medium Alerts     : {BLU}{sevs.get("Medium",0)}{R}')
    print(f'  Low Alerts        : {GRN}{sevs.get("Low",0)}{R}')
    print(f'  Low False+ Rate   : {GRN}{fps.get("Low",0)}{R} alerts')
    print(f'\n{BLD}  TOP ATTACK TYPES{R}')
    for atk,cnt in atks.most_common(5):
        bar='#'*cnt
        print(f'  {YEL}{atk:<25}{R} {cnt:>3}x  {bar}')
    print(f'\n{BLD}  MITRE ATT&CK TACTICS{R}')
    for tac,cnt in mitres.most_common(5):
        print(f'  {BLU}{tac:<25}{R} {cnt:>3} alerts')
    print(f'\n{BLD}  RECOMMENDED ACTIONS{R}')
    seen_actions=set()
    for e in entries:
        act=e.get('recommended_action','')
        if act and act not in seen_actions:
            print(f'  >> {act}')
            seen_actions.add(act)
            if len(seen_actions)>=3: break
    print(f'\n{BLD}  RECENT AI ANALYSES{R}')
    for e in entries[-5:]:
        sev=e.get('severity','?')
        sc={'Critical':RED,'High':YEL,'Medium':BLU,'Low':GRN}
        c=sc.get(sev,'')
        atk=e.get('attack_type','?')
        rid=e.get('rule_id','?')
        ts=e.get('timestamp','?')[:16]
        print(f'  {c}[{sev}]{R} {atk} | Rule:{rid} | {ts}')
    print('\n'+CYN+'='*W+R+'\n')

if __name__=='__main__':
    entries=load_entries()
    if not entries:
        print('No triage data yet. Run alert_poller.py first.')
    else:
        print_report(entries)
