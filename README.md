# AI-Assisted SOC

Automated SOC with local AI triage, SOAR, and live dashboard.
No cloud. No API keys. Runs entirely on Kali Linux.

**Repo:** https://github.com/Hax0023/AI-SOC

---

## Architecture

```
Kali Linux
    ↓
Wazuh Agent  →  Wazuh Manager  →  OpenSearch Indexer
                      ↓
Suricata IDS      alerts.json
(64,646 rules)        ↓
    ↓          Alert Poller (30s)
eve.json              ↓
    ↓         Ollama LLaMA3.2:1b
    └─────────────→  AI Triage
                      ↓
               SOAR Engine
                ↓       ↓
          block_ip   log_incident
                      ↓
           Live Dashboard :8080
```

---

## Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| OS | Kali Linux 2024+ | Kali Linux 2025+ |
| RAM | 8 GB | 16 GB |
| Disk | 40 GB free | 80 GB SSD |
| CPU | 4 cores | 8 cores |

---

## Quick Install

```bash
git clone https://github.com/Hax0023/AI-SOC.git
cd AI-SOC
bash install.sh
```

The installer will:
- Prompt you to set a Wazuh admin password
- Install Docker, Suricata, Python dependencies
- Deploy Wazuh v4.14.3 (3 containers)
- Install Ollama and pull LLaMA3.2:1b (~1.3GB)
- Register the Wazuh agent
- Deploy all custom detection rules
- Configure Suricata with Emerging Threats ruleset

---

## Daily Use

```bash
bash ~/AI-SOC/soc_launcher.sh
```

Auto-detects IP, starts all services, updates rules.

- Wazuh Dashboard → https://localhost
- SOC Dashboard   → http://localhost:8080

---

## Detection Rules

| Rule ID | Level | Detects | MITRE |
|---------|-------|---------|-------|
| 100001 | 10 | SSH login non-existent user | T1110.001 |
| 100002 | 14 | SSH brute force 8+ attempts | T1110 |
| 100003 | 10 | SSH auth failure real user | T1110 |
| 100004 | 14 | SSH brute force real user | T1110 |
| 100005 | 8 | Network ping / ICMP recon | T1018 |
| 100010 | 12 | Sudo privilege escalation | T1548.003 |
| 100011 | 12 | New user account created | T1136.001 |
| 100012 | 14 | Critical file modified | T1098 |

---

## SOAR Playbooks

| Playbook | Trigger | Actions |
|----------|---------|---------|
| ssh_brute_force.yml | SSH attacks | Block IP + log + alert |
| network_recon.yml | Ping / recon | Log + alert |
| privilege_escalation.yml | Sudo / new user | Log + alert |

---

## Adding New Rules

### Wazuh Rule

Edit `soc-ai/rules/local_rules.xml`, add inside `<group>`:

```xml
<rule id="100020" level="12">
  <if_sid>PARENT_RULE_ID</if_sid>
  <match>text to match in log</match>
  <description>SOC-LAB: Your description</description>
  <mitre><id>T1234</id></mitre>
  <group>your_category</group>
</rule>
```

Deploy:
```bash
docker cp soc-ai/rules/local_rules.xml \
  single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 \
  /var/ossec/bin/wazuh-control restart
```

Test before deploying:
```bash
echo "your log line" | docker exec -i \
  single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest \
  2>&1 | grep -E "id:|level:|Alert to be"
```

### Suricata Rule

Edit `/etc/suricata/rules/ping_detect.rules`:

```
alert tcp any any -> YOUR_IP any (
  msg:"SOC-LAB: Your alert";
  flags:S;
  classtype:network-scan;
  sid:9900020; rev:1;
)
```

Reload without restart:
```bash
sudo suricatasc -c reload-rules
```

### SOAR Playbook

Create `soc-ai/playbooks/your_playbook.yml`:

```yaml
name: Your Response Name
trigger:
  attack_type: "keyword AI will match"
  min_severity: "High"
actions:
  - name: block_ip
    type: firewall_block
    enabled: true
  - name: log_incident
    type: log_incident
    enabled: true
  - name: notify
    type: console_alert
    enabled: true
```

---

## Project Structure

```
AI-SOC/
├── install.sh
├── soc_launcher.sh
├── requirements.txt
└── soc-ai/
    ├── .env.example
    ├── modules/
    │   ├── ai_triage.py
    │   ├── soar_engine.py
    │   ├── live_dashboard.py
    │   └── soc_report.py
    ├── playbooks/
    │   ├── ssh_brute_force.yml
    │   ├── network_recon.yml
    │   └── privilege_escalation.yml
    └── rules/
        └── local_rules.xml
```

---

## Useful Commands

```bash
# View live SOAR output
tail -f /tmp/soar.log

# Shift summary report
cd ~/AI-SOC/soc-ai && source venv/bin/activate
python3 modules/soc_report.py

# Check agent status
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

# Simulate SSH brute force
for i in $(seq 1 20); do ssh -o BatchMode=yes fakeuser@127.0.0.1 2>/dev/null; done

# Watch Suricata alerts live
tail -f /var/log/suricata/fast.log

# Count todays alerts
docker exec single-node-wazuh.manager-1 wc -l /var/ossec/logs/alerts/alerts.json
```

---

## Tools Used

| Tool | Version | Purpose |
|------|---------|--------|
| Wazuh | 4.14.3 | SIEM + EDR |
| Suricata | 8.0.3 | Network IDS |
| Ollama | 0.18.2 | Local LLM runtime |
| LLaMA3.2 | 1b | AI triage model |
| Python | 3.13 | SOC automation |
| Docker | 27.5.1 | Containers |

---

## Notes

- All AI runs locally - no data leaves your machine
- Wazuh login: `admin` / password set during install
- Never commit `.env` - it contains credentials
- SID `9900001+` for custom Suricata rules
- Rule ID `100001+` for custom Wazuh rules
- Run `bash ~/AI-SOC/soc_launcher.sh` after every reboot
