# AI-Assisted SOC on Kali Linux

A fully automated Security Operations Center built on open-source tools,
featuring local AI-powered alert triage, automated SOAR responses,
and a live web dashboard — no cloud, no API keys required.

## Architecture
```
Kali Linux (monitored endpoint)
      ↓
Wazuh Agent → Wazuh Manager → OpenSearch Indexer
                                      ↓
Suricata IDS (network traffic)   Alerts JSON
                                      ↓
                          Python Alert Poller
                                      ↓
                      Ollama LLaMA3.2:1b (local AI)
                                      ↓
                         SOAR Playbook Engine
                                      ↓
                    Live Dashboard (localhost:8080)
```

## Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| OS | Kali Linux 2024+ | Kali Linux 2025+ |
| RAM | 8 GB | 16 GB |
| Disk | 40 GB free | 80 GB SSD |
| CPU | 4 cores | 8 cores |

## Quick Install
```bash
git clone https://github.com/YOUR_USERNAME/AI-SOC.git
cd AI-SOC
bash install.sh
```

## Daily Use
```bash
bash ~/AI-SOC/soc_launcher.sh
```

Opens:
- Wazuh SIEM Dashboard → https://localhost (admin / SecretPassword)
- AI-SOC Live Dashboard → http://localhost:8080

## What Was Built

| Phase | Component | Description |
|-------|-----------|-------------|
| 1 | Foundation | Wazuh v4.14.3 + Suricata IDS + Agent |
| 2 | Detection | 64,646 rules + custom MITRE-tagged rules |
| 3 | AI Triage | Local LLaMA3.2 analyzing every alert |
| 4 | SOAR | Automated playbook response engine |
| 5 | Dashboard | Live web UI + shift report + auto-launcher |

## Project Structure
```
AI-SOC/
├── install.sh              # One-command installer
├── soc_launcher.sh         # Daily start script
├── requirements.txt        # Python dependencies
├── wazuh-docker/           # Wazuh SIEM stack
└── soc-ai/
    ├── .env.example        # Config template
    ├── modules/
    │   ├── ai_triage.py    # AI analysis engine
    │   ├── soar_engine.py  # Automated response
    │   ├── live_dashboard.py
    │   ├── alert_poller.py
    │   └── soc_report.py
    ├── playbooks/
    │   ├── ssh_brute_force.yml
    │   └── network_recon.yml
    └── rules/
        └── local_rules.xml
```

## Detection Coverage

- SSH Brute Force (MITRE T1110)
- Credential Stuffing (MITRE T1110.004)
- Network Reconnaissance / ICMP (MITRE T1018)
- Suricata Emerging Threats ruleset (64,646 rules)

## Tools Used

Wazuh · OpenSearch · Suricata · Ollama · LLaMA3.2 · Python · Docker · iptables
