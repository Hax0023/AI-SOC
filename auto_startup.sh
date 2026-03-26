#!/bin/bash
# Run this after every reboot to restore full SOC
export PATH="$HOME/.local/bin:$PATH"

# Wait for Docker
sleep 10

# Start Ollama
pgrep -x ollama > /dev/null || nohup ollama serve > /tmp/ollama.log 2>&1 &

# Start full SOC
bash ~/AI-SOC/soc_launcher.sh
