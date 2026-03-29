#!/bin/bash
RED='\033[91m';GRN='\033[92m';CYN='\033[96m';BLD='\033[1m';R='\033[0m'
step(){ echo -e "${BLD}[*]${R} $1"; }
ok(){   echo -e "${GRN}[+]${R} $1"; }
echo -e "\n${BLD}${CYN}=== AI-ASSISTED SOC — hax0023 ===${R}"
echo -e "${CYN}    $(date '+%Y-%m-%d %H:%M:%S')${R}\n"
KALI_IP=$(ip -br a show eth0 | awk '{print $3}' | cut -d/ -f1)
step "Kali IP: $KALI_IP"
step "Starting Wazuh..."
cd ~/AI-SOC/wazuh-docker/single-node
docker compose up -d 2>/dev/null
sleep 8
MANAGER_IP=$(docker inspect single-node-wazuh.manager-1 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d[0]['NetworkSettings']['Networks'].values())[0]['IPAddress'])" 2>/dev/null)
ok "Manager IP: $MANAGER_IP"
step "Fixing agent config..."
sudo sed -i "s|<address>.*</address>|<address>${MANAGER_IP}</address>|g" /var/ossec/etc/ossec.conf 2>/dev/null
sudo systemctl restart wazuh-agent 2>/dev/null
ok "Agent restarted pointing to $MANAGER_IP"
sleep 6
AGENT_OK=$(docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l 2>/dev/null | grep "kali-soc-lab" | grep -c "Active")
if [ "$AGENT_OK" -eq 0 ]; then
  step "Agent disconnected - re-registering..."
  OLD_ID=$(docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l 2>/dev/null | grep "kali-soc-lab" | grep -oP "ID: K[0-9]+")
  [ -n "$OLD_ID" ] && printf "y
" | docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/manage_agents -r "$OLD_ID" 2>/dev/null
  sudo bash -c 'echo "" > /var/ossec/etc/client.keys'
  sudo /var/ossec/bin/agent-auth -m "$MANAGER_IP" -p 1515 -A "kali-soc-lab" 2>/dev/null
  sudo systemctl restart wazuh-agent 2>/dev/null
  ok "Agent re-registered"
fi
step "Starting Suricata..."
sudo systemctl start suricata 2>/dev/null
ok "Suricata active"
step "Updating ping rules for $KALI_IP..."
printf 'alert icmp any any -> %s any (msg:"SOC-LAB: ICMP Ping to Kali"; itype:8; classtype:network-scan; sid:9900001; rev:3;)\nalert icmp 10.0.0.0/8 any -> %s any (msg:"SOC-LAB: Ping from Windows host"; itype:8; classtype:network-scan; sid:9900002; rev:3;)\n' "$KALI_IP" "$KALI_IP" | sudo tee /etc/suricata/rules/ping_detect.rules > /dev/null
sudo suricatasc -c reload-rules > /dev/null 2>&1
ok "Ping rules updated for $KALI_IP"
step "Starting Ollama..."
export PATH="$HOME/.local/bin:$PATH"
pgrep -x ollama > /dev/null || (nohup ollama serve > /tmp/ollama.log 2>&1 & sleep 3)
ok "Ollama on :11434"
step "Starting SOAR + Dashboard..."
cd ~/AI-SOC/soc-ai && source venv/bin/activate
pkill -f soar_engine 2>/dev/null; pkill -f live_dashboard 2>/dev/null; sleep 2
nohup python3 -u modules/live_dashboard.py > /tmp/dashboard.log 2>&1 &
nohup python3 -u modules/soar_engine.py > /tmp/soar.log 2>&1 &
ok "SOC AI services started"
echo -e "\n${BLD}${GRN}=== SOC FULLY OPERATIONAL ===${R}"
echo -e "${GRN}  Kali IP  : $KALI_IP${R}"
echo -e "${GRN}  Manager  : $MANAGER_IP${R}"
echo -e "${GRN}  Wazuh    : https://localhost${R}"
echo -e "${GRN}  SOC Dash : http://localhost:8080${R}"
echo -e "${GRN}  SOAR log : tail -f /tmp/soar.log${R}\n"
