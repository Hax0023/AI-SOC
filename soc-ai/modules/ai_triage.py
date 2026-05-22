import requests,json,os,time
from datetime import datetime,timezone

def _cfg():
    c={}
    try:
        fh=open(os.path.expanduser('~/AI-SOC/soc-ai/.env'))
        for l in fh:
            l=l.strip()
            if l and '=' in l and not l.startswith('#'):
                k,v=l.split('=',1);c[k.strip()]=v.strip()
    except:pass
    return c

C=_cfg()
URL=C.get('OLLAMA_HOST','http://localhost:11434')+'/api/generate'
MDL=C.get('OLLAMA_MODEL','llama3.2:1b')
LOG=os.path.expanduser('~/AI-SOC/soc-ai/logs/triage_log.jsonl')
os.makedirs(os.path.dirname(LOG),exist_ok=True)

# Known rules classified deterministically — LLM only explains, never classifies
RULE_MAP={
    '100001':{'attack_type':'SSH Brute Force','severity':'High','mitre_tactic':'Credential Access','false_positive_chance':'Low'},
    '100002':{'attack_type':'SSH Brute Force','severity':'High','mitre_tactic':'Credential Access','false_positive_chance':'Low'},
    '100003':{'attack_type':'SSH Login Non-Existent User','severity':'High','mitre_tactic':'Credential Access','false_positive_chance':'Low'},
    '100004':{'attack_type':'Privilege Escalation via Sudo','severity':'Critical','mitre_tactic':'Privilege Escalation','false_positive_chance':'Medium'},
    '100005':{'attack_type':'Network Reconnaissance','severity':'Medium','mitre_tactic':'Discovery','false_positive_chance':'Medium'},
    '100010':{'attack_type':'Privilege Escalation via Sudo','severity':'Critical','mitre_tactic':'Privilege Escalation','false_positive_chance':'Low'},
    '533':{'attack_type':'Port Status Change','severity':'Low','mitre_tactic':'Discovery','false_positive_chance':'High'},
    '5710':{'attack_type':'SSH Login Attempt','severity':'Medium','mitre_tactic':'Credential Access','false_positive_chance':'Medium'},
    '5712':{'attack_type':'SSH Brute Force','severity':'High','mitre_tactic':'Credential Access','false_positive_chance':'Low'},
    '5720':{'attack_type':'SSH Authentication Failure','severity':'Medium','mitre_tactic':'Credential Access','false_positive_chance':'Medium'},
    '2502':{'attack_type':'Successful SSH Login','severity':'Low','mitre_tactic':'Lateral Movement','false_positive_chance':'High'},
}

def analyze_alert(alert):
    rule=alert.get('rule',{})
    agent=alert.get('agent',{})
    data=alert.get('data',{})
    rid=str(rule.get('id','?'))
    lvl=str(rule.get('level','?'))
    desc=str(rule.get('description','?'))
    aname=str(agent.get('name','?'))
    aip=str(agent.get('ip','?'))
    mitre=str(rule.get('mitre',{}).get('id','N/A'))
    dstr=json.dumps({k:str(v)[:60] for k,v in data.items() if k not in ["full_log","previous_log"]},default=str)[:200]

    known=RULE_MAP.get(rid)
    if known:
        # Known rule — only ask LLM to explain and recommend
        prompt=(
            f'You are a SOC analyst. This alert is already classified.\n'
            f'Attack type: {known["attack_type"]}\n'
            f'Rule description: {desc}\n'
            f'Agent: {aname} ({aip})\n'
            f'Data: {dstr}\n\n'
            'Output ONLY a flat JSON object with exactly these two fields:\n'
            '{"recommended_action":"<one specific action for this alert>",'
            '"explanation":"<exactly 2 sentences about what happened>"}'
        )
    else:
        # Unknown rule — ask LLM to fully classify
        prompt=(
            f'You are a SOC analyst reviewing: {desc}.\n'
            'Output ONLY a flat JSON object. No markdown, no extra text.\n\n'
            f'RuleID:{rid} Level:{lvl}/15\n'
            f'Agent:{aname}({aip}) MITRE:{mitre}\n'
            f'Data:{dstr}\n\n'
            'Reply with exactly this JSON:\n'
            '{"severity":"High","attack_type":"<attack name>",'
            '"mitre_tactic":"<tactic name>",'
            '"false_positive_chance":"Low",'
            '"recommended_action":"<specific action>",'
            '"explanation":"<2 sentences about this alert>"}'
        )

    try:
        r=requests.post(URL,json={'model':MDL,'prompt':prompt,'stream':False},timeout=90)
        raw=r.json().get('response','{}')
        s,e=raw.find('{'),raw.rfind('}')+1
        res=json.loads(raw[s:e]) if s>=0 and e>s else {'error':'parse_failed'}
    except Exception as ex:
        # Retry once
        try:
            time.sleep(10)
            r=requests.post(URL,json={'model':MDL,'prompt':prompt,'stream':False},timeout=90)
            raw=r.json().get('response','{}')
            s,e=raw.find('{'),raw.rfind('}')+1
            res=json.loads(raw[s:e]) if s>=0 and e>s else {'error':'parse_failed'}
        except Exception as ex2:
            res={'error':str(ex2)}

    # Merge known fields on top so they are never overwritten by LLM
    if known:
        res.update(known)
    res.update({'rule_id':rid,'rule_level':lvl,'agent':aname,
        'timestamp':datetime.now(timezone.utc).isoformat(),
        'original_description':desc})
    return res

def log_triage(res):
    with open(LOG,'a') as f:
        f.write(json.dumps(res)+'\n')

def print_triage(res):
    clr={'Critical':'\033[91m','High':'\033[93m','Medium':'\033[94m','Low':'\033[92m'}
    R='\033[0m'
    sev=res.get('severity','Unknown')
    c=clr.get(sev,'')
    sep='='*58
    print('\n'+sep)
    print(c+'  ['+sev+']  '+res.get('attack_type','?')+R)
    print(sep)
    print('  Rule    : '+str(res.get('rule_id'))+' (L'+str(res.get('rule_level'))+')')
    print('  Desc    : '+str(res.get('original_description',''))[:55])
    print('  Agent   : '+str(res.get('agent','?')))
    print('  MITRE   : '+str(res.get('mitre_tactic','N/A')))
    print('  False+  : '+str(res.get('false_positive_chance','?')))
    print('  Action  : '+str(res.get('recommended_action','N/A')))
    print('  Summary : '+str(res.get('explanation','N/A')))
    print('  Time    : '+str(res.get('timestamp','?')))
    print(sep+'\n')

if __name__=='__main__':
    test={'rule':{'id':'100001','level':'10',
        'description':'SOC-LAB: SSH Brute Force 8 attempts from 127.0.0.1',
        'mitre':{'id':['T1110']},'groups':['brute_force']},
        'agent':{'name':'kali-soc-lab','ip':'172.18.0.1'},
        'data':{'srcip':'127.0.0.1','srcuser':'fakeuser','attempts':8}}
    print('[*] Testing AI triage...')
    t=time.time()
    res=analyze_alert(test)
    print(f'[*] Done in {time.time()-t:.1f}s')
    print_triage(res)
    log_triage(res)
