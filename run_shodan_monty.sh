#!/bin/bash

# Set script directory
SCRIPT_DIR="/home/azureuser/scripts"
PROJECT_DIR="/home/azureuser/projects/Monty"
DATA_DIR="${PROJECT_DIR}/data"
QUERIES_DIR="${PROJECT_DIR}/queries/shodan/formatted"
QUERIES_FILE="${DATA_DIR}/formatted_shodan_queries"
LOG_DIR="${PROJECT_DIR}/logs"
DATE=$(date '+%Y-%m-%d')
APIKEY_FILE="/home/azureuser/scripts/shodanapikey"

# Check if API key file exists and is readable
if [ ! -f "$APIKEY_FILE" ]; then
    echo "Error: Shodan API key file not found at $APIKEY_FILE" >> "${LOG_DIR}/shodan_${DATE}.log"
    exit 1
fi

# Read API key from file
SHODAN_API_KEY=$(cat "$APIKEY_FILE")

# Create logs directory if it doesn't exist
mkdir -p ${LOG_DIR}

# Run Shodan script and log output
echo "Starting Shodan Query Manager at $(date)" >> "${LOG_DIR}/shodan_${DATE}.log"
cd ${PROJECT_DIR}
git pull --rebase origin centrica_fork_queries
cd ${SCRIPT_DIR}
source advinfra_env/bin/activate
python3 shodan_query_manager.py --apikey "$SHODAN_API_KEY" --projectlabel "CTI-IOA" --queries "${QUERIES_FILE}" 2>&1 | tee -a "${LOG_DIR}/shodan_new_${DATE}.log"
cd ${PROJECT_DIR}
git add .
git commit -m "Automated cron triggered update: ${DATE}"
git push origin main
echo "Finished Shodan Query Manager at $(date)" >> "${LOG_DIR}/shodan_${DATE}.log"
