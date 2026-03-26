#!/bin/bash
set -e
GRN='\033[92m';YEL='\033[93m';CYN='\033[96m';BLD='\033[1m';R='\033[0m'
RED='\033[91m'
step(){ echo -e "\n${BLD}${CYN}[*] $1${R}"; }
ok(){   echo -e "${GRN}[+] $1${R}"; }
warn(){ echo -e "${YEL}[!] $1${R}"; }
fail(){ echo -e "${RED}[-] $1${R}"; exit 1; }

echo -e "\n${BLD}${CYN}=== AI-ASSISTED SOC INSTALLER ===${R}\n"

# Prompt for Wazuh password at install time
echo -e "${BLD}Set your Wazuh admin password:${R}"
read -s -p "Password (min 8 chars): " WAZUH_PASSWORD; echo
read -s -p "Confirm password: " WAZUH_PASSWORD2; echo
[[ "$WAZUH_PASSWORD" != "$WAZUH_PASSWORD2" ]] && fail "Passwords do not match."
[[ ${#WAZUH_PASSWORD} -lt 8 ]] && fail "Password must be at least 8 characters."
ok "Password set"
[[ $(id -u) -eq 0 ]] && fail "Do not run as root."
command -v apt &>/dev/null || fail "Requires Debian/Kali Linux."
RAM=$(free -g | awk '/Mem/{print $2}')
DISK=$(df -BG / | awk 'NR==2{print $4}' | tr -d G)
[[ $RAM -lt 7 ]] && warn "Low RAM: ${RAM}GB. Recommend 8GB+."
[[ $DISK -lt 40 ]] && fail "Need 40GB free. Found ${DISK}GB."
ok "System OK — RAM:${RAM}GB Disk:${DISK}GB free"

step "Installing system packages..."
sudo apt update -q
sudo apt install -y docker.io docker-compose curl wget git \
  python3-pip python3-venv jq net-tools suricata suricata-update
sudo systemctl enable docker && sudo systemctl start docker
sudo usermod -aG docker $USER
ok "Packages installed"

step "Setting kernel parameters..."
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf > /dev/null
sudo fallocate -l 4G /swapfile 2>/dev/null || true
sudo chmod 600 /swapfile 2>/dev/null || true
sudo mkswap /swapfile 2>/dev/null || true
sudo swapon /swapfile 2>/dev/null || true
ok "Kernel params set"

step "Installing Ollama..."
OLLAMA_BIN="$HOME/.local/bin"
mkdir -p "$OLLAMA_BIN"
if [[ ! -f "$OLLAMA_BIN/ollama" ]]; then
  curl -fsSL "https://github.com/ollama/ollama/releases/download/v0.18.2/ollama-linux-amd64.tar.zst" \
    -o /tmp/ollama.tar.zst
  mkdir -p /tmp/oi
  tar --use-compress-program=zstd -xf /tmp/ollama.tar.zst -C /tmp/oi/
  cp /tmp/oi/bin/ollama "$OLLAMA_BIN/ollama"
  chmod +x "$OLLAMA_BIN/ollama"
  rm -rf /tmp/ollama.tar.zst /tmp/oi
fi
export PATH="$OLLAMA_BIN:$PATH"
ok "Ollama installed"

step "Starting Ollama and pulling llama3.2:1b model (~1.3GB)..."
nohup ollama serve > /tmp/ollama.log 2>&1 &
sleep 5
ollama pull llama3.2:1b
ok "LLaMA3.2:1b ready"

step "Deploying Wazuh SIEM v4.14.3..."
cd ~/AI-SOC/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
sudo chown -R $USER:docker config/wazuh_indexer_ssl_certs/
sudo chmod -R 755 config/wazuh_indexer_ssl_certs/
docker compose up -d
ok "Wazuh stack started — waiting 30s for indexer..."
sleep 30

step "Setting up Python environment..."
cd ~/AI-SOC/soc-ai
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt --quiet
cp .env.example .env
sed -i "s|WAZUH_PASS=.*|WAZUH_PASS=${WAZUH_PASSWORD}|" .env
ok "Python venv ready"

step "Configuring Suricata..."
sudo suricata-update
KALI_IP=$(ip -br a show eth0 | awk '{print $3}' | cut -d/ -f1)
sudo printf 'alert icmp any any -> %s any (msg:"SOC-LAB: ICMP Ping to Kali"; itype:8; classtype:network-scan; sid:9900001; rev:1;)\n' "$KALI_IP" | \
  sudo tee /etc/suricata/rules/ping_detect.rules > /dev/null
sudo sed -i '/^rule-files:/a\  - /etc/suricata/rules/ping_detect.rules' /etc/suricata/suricata.yaml
sudo systemctl enable suricata && sudo systemctl restart suricata
ok "Suricata configured"

step "Installing Wazuh agent..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update -q
MANAGER_IP=$(docker inspect single-node-wazuh.manager-1 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
  print(list(d[0]['NetworkSettings']['Networks'].values())[0]['IPAddress'])")
WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="kali-soc-lab" \
  sudo apt install -y wazuh-agent
sudo sed -i "s|<address>.*</address>|<address>${MANAGER_IP}</address>|g" \
  /var/ossec/etc/ossec.conf
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sleep 5
sudo /var/ossec/bin/agent-auth -m "$MANAGER_IP" -p 1515 -A "kali-soc-lab"
sudo systemctl restart wazuh-agent
ok "Wazuh agent registered"

step "Deploying custom detection rules..."
docker cp ~/AI-SOC/soc-ai/rules/local_rules.xml \
  single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 \
  /var/ossec/bin/wazuh-control restart 2>&1 | tail -2
ok "Custom rules deployed"

echo -e "\n${BLD}${GRN}=== INSTALLATION COMPLETE ===${R}"
echo -e "${GRN}  Wazuh Dashboard : https://localhost${R}"
echo -e "${GRN}  SOC Dashboard   : http://localhost:8080${R}"
echo -e "${GRN}  Login           : admin / (password set during install)${R}"
echo -e "${G
