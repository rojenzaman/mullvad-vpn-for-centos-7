#!/bin/bash

# Mullvad VPN automatic setup script with integrated kill switch (IPv4 + IPv6)
# and utility scripts generation. Provides DNS leak prevention, error handling,
# and supports --generate-only, --default, and --dns1=<IP> arguments.
# 
# Includes a function to detect and disable firewalld so that iptables-persistent
# works properly on CentOS 7.

set -e  # Exit immediately if a command exits with a non-zero status

# Logging function
log() {
    echo -e "[`date '+%Y-%m-%d %H:%M:%S'`] $@"
}

# Error handling function
error_exit() {
    echo -e "[`date '+%Y-%m-%d %H:%M:%S'`] ERROR: $1" >&2
    exit 1
}

# Help function
show_help() {
    cat << EOF
Mullvad VPN Setup Script with IPv4 + IPv6 Kill Switch

Usage:
  $0 --default [--dns1=<IP>]        Run the full setup (system configurations + script generation)
  $0 --generate-only                Generate kill-switch.sh, restart.sh, and status.sh without system changes
  $0 --help                         Display this help message

Options:
  --dns1=<IP>    Specify the DNS1 IP address to use for IPv4 (default: 100.64.0.63)

Description:
  This script automates Mullvad VPN setup on a CentOS 7 server. It:
    - Stops/disables existing Mullvad OpenVPN services
    - Removes old configs in /etc/openvpn/
    - Copies new Mullvad configs to /etc/openvpn/
    - Enables/starts Mullvad's systemd service
    - Updates DNS settings in network config
    - Generates the kill-switch.sh (with IPv4 + IPv6), restart.sh, and status.sh scripts
    - Immediately applies and saves iptables + ip6tables rules (if --default)
    - Ensures IPv6 traffic is also restricted to the VPN tunnel only
    - Checks if firewalld is installed or active, disables it to avoid conflicts

  Use --generate-only if you only want the scripts generated, without touching system configs or services.

EOF
}

# Default DNS1 address (Mullvad DNS)
DNS1_DEFAULT="100.64.0.63"

# Parse arguments
if [[ "$#" -eq 0 ]]; then
    show_help
    exit 0
fi

GENERATE_ONLY=false
DEFAULT_MODE=false
DNS1="$DNS1_DEFAULT"

for arg in "$@"; do
    case "$arg" in
        --generate-only)
            GENERATE_ONLY=true
            ;;
        --default)
            DEFAULT_MODE=true
            ;;
        --dns1=*)
            DNS1="${arg#*=}"
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            show_help
            exit 1
            ;;
    esac
done

if [[ "$GENERATE_ONLY" == false && "$DEFAULT_MODE" == false ]]; then
    echo "No valid arguments provided."
    show_help
    exit 1
fi

if [[ "$GENERATE_ONLY" == true ]]; then
    log "Running in generate-only mode: System configurations, iptables, and ip6tables will not be modified."
fi

if [[ "$DEFAULT_MODE" == true ]]; then
    log "Running in default mode: Full setup will be performed."
    log "Using DNS1 address: $DNS1"
fi

# ---------------------------------------------------------------
# Function to check and disable firewalld if it is installed/running
# ---------------------------------------------------------------
disable_firewalld_if_needed() {
    log "Checking firewalld status..."
    # Check if firewalld package is installed
    if yum list installed firewalld &>/dev/null; then
        log "firewalld package is installed."
        # Check if firewalld service is active
        if systemctl is-active --quiet firewalld; then
            log "firewalld is running. Stopping and disabling..."
            systemctl stop firewalld || error_exit "Failed to stop firewalld"
            systemctl disable firewalld || error_exit "Failed to disable firewalld"
            log "firewalld has been stopped and disabled."
        else
            log "firewalld service is not active. No action needed."
        fi
    else
        log "firewalld package is not installed. No action needed."
    fi
}

# Get the directory where the script is located
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
mullvad_dir="$script_dir"

# Find the Mullvad configuration directory that contains update-resolv-conf
config_dir=$(find "$mullvad_dir" -type f -name 'update-resolv-conf' -exec dirname {} \; | head -n 1)
if [[ -z "$config_dir" ]]; then
    error_exit "Mullvad configuration directory not found in $mullvad_dir"
else
    log "Mullvad configuration directory found at $config_dir"
fi

# If not in generate-only mode, proceed with system modifications
if [[ "$GENERATE_ONLY" == false ]]; then
    # First, ensure firewalld is disabled so iptables services can work properly
    disable_firewalld_if_needed

    # Stop and disable Mullvad OpenVPN services
    log "Stopping and disabling Mullvad OpenVPN services..."
    for conf_file in /etc/openvpn/mullvad_*.conf; do
        if [[ -f "$conf_file" ]]; then
            conf_name=$(basename "$conf_file")
            service_name="openvpn@${conf_name%.conf}.service"
            if systemctl is-active --quiet "$service_name"; then
                systemctl stop "$service_name" || error_exit "Failed to stop $service_name"
                log "$service_name stopped"
            fi
            if systemctl is-enabled --quiet "$service_name"; then
                systemctl disable "$service_name" || error_exit "Failed to disable $service_name"
                log "$service_name disabled"
            fi
        fi
    done

    # Remove existing configurations in /etc/openvpn/
    log "Removing existing OpenVPN configurations in /etc/openvpn/..."
    rm -rf /etc/openvpn/* || error_exit "Failed to remove existing OpenVPN configurations"

    # Give execute permissions to update-resolv-conf script
    log "Setting execute permissions for update-resolv-conf script..."
    update_resolv_conf="$config_dir/update-resolv-conf"
    if [[ -f "$update_resolv_conf" ]]; then
        chmod +x "$update_resolv_conf" || error_exit "Failed to set execute permissions on update-resolv-conf"
    else
        error_exit "update-resolv-conf script not found at $update_resolv_conf"
    fi

    # Move Mullvad configuration files to /etc/openvpn/
    log "Moving Mullvad configuration files to /etc/openvpn/..."
    cp -r "$config_dir"/* /etc/openvpn/ || error_exit "Failed to copy Mullvad configuration files"

    # Detect the Mullvad configuration file and enable the corresponding systemd service
    log "Enabling Mullvad systemd service..."
    mullvad_conf=$(basename /etc/openvpn/mullvad_*.conf)
    if [[ -f "/etc/openvpn/$mullvad_conf" ]]; then
        service_name="openvpn@${mullvad_conf%.conf}.service"
        systemctl enable "$service_name" || error_exit "Failed to enable $service_name"
        log "$service_name enabled"
    else
        error_exit "Mullvad configuration file not found in /etc/openvpn/"
    fi

    # Update DNS1 line in the network configuration (eth0 assumed)
    log "Updating DNS1 line in network configuration..."
    network_config="/etc/sysconfig/network-scripts/ifcfg-eth0"
    if [[ -f "$network_config" ]]; then
        if grep -q '^DNS1=' "$network_config"; then
            sed -i "s/^DNS1=.*/DNS1=$DNS1/" "$network_config" || error_exit "Failed to update DNS1 in $network_config"
            log "DNS1 in $network_config updated to $DNS1"
        else
            echo "DNS1=$DNS1" >> "$network_config" || error_exit "Failed to add DNS1 to $network_config"
            log "DNS1=$DNS1 added to $network_config"
        fi
    else
        error_exit "Network configuration file $network_config not found"
    fi
else
    # In generate-only mode, we just need mullvad_conf and service_name
    mullvad_conf_file=$(find "$config_dir" -name 'mullvad_*.conf' -print -quit)
    if [[ -f "$mullvad_conf_file" ]]; then
        mullvad_conf=$(basename "$mullvad_conf_file")
        service_name="openvpn@${mullvad_conf%.conf}.service"
    else
        error_exit "Mullvad configuration file not found in $config_dir"
    fi
fi

# Generate kill-switch.sh based on the OpenVPN configuration
log "Generating kill-switch.sh script based on the OpenVPN configuration..."

if [[ "$GENERATE_ONLY" == true ]]; then
    OPENVPN_CONF="$config_dir/$mullvad_conf"
else
    OPENVPN_CONF="/etc/openvpn/$mullvad_conf"
fi

KILL_SWITCH_SCRIPT="$mullvad_dir/iptables/kill-switch.sh"

if [[ ! -f "$OPENVPN_CONF" ]]; then
    error_exit "OpenVPN configuration file not found at $OPENVPN_CONF"
fi

# Extract remote server IPs and ports from the OpenVPN config (IPv4 or domain)
REMOTE_ENTRIES=$(grep '^remote ' "$OPENVPN_CONF" | sed 's/#.*//')

if [[ -z "$REMOTE_ENTRIES" ]]; then
    error_exit "No 'remote' entries found in $OPENVPN_CONF (cannot determine Mullvad server IP/port)."
fi

declare -A PORTS
declare -A IPS

while read -r line; do
    read -a tokens <<< "$line"
    IP="${tokens[1]}"
    PORT="${tokens[2]}"
    IPS["$IP"]=1
    PORTS["$PORT"]=1
done <<< "$REMOTE_ENTRIES"

UNIQUE_IPS=$(echo "${!IPS[@]}" | tr ' ' ',')
UNIQUE_PORTS=$(echo "${!PORTS[@]}" | tr ' ' ',')

mkdir -p "$(dirname "$KILL_SWITCH_SCRIPT")"

#
# ENHANCED kill-switch.sh with IPv4 + IPv6 blocking rules
#
cat << EOF > "$KILL_SWITCH_SCRIPT"
#!/bin/bash

# ============================
# Enhanced Mullvad Kill Switch (IPv4 + IPv6)
# ============================
# This script enforces:
# 1. All outbound IPv4 traffic (except local LAN) must go via tun0.
# 2. All outbound IPv6 traffic must also go via tun0.
# 3. DNS queries only to Mullvad IPv4 DNS ($DNS1) via tun0 (preventing DNS leaks).
# 4. Only Mullvad server IPs/ports are allowed outbound on eth0 (UDP) before tun0 is up.
# 5. Local LAN traffic (192.168.1.0/24) is always allowed for PBX or internal devices.
# 6. IPv6 traffic (if used by Mullvad) is restricted to tun0, preventing IPv6 leaks.

########## IPv4 iptables ##########
# 1) Flush existing IPv4 rules
iptables -F
iptables -X

# 2) Default DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# 3) Allow all loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# 4) Allow traffic via VPN (tun0)
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A OUTPUT -o tun0 -j ACCEPT

# 5) Allow local LAN traffic (192.168.1.0/24)
iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT
iptables -A OUTPUT -d 192.168.1.0/24 -j ACCEPT

# 6) Allow outbound to Mullvad VPN servers (IPv4) - necessary before tun0 is up
iptables -A OUTPUT -p udp -m multiport --dports $UNIQUE_PORTS -d $UNIQUE_IPS -j ACCEPT
iptables -A INPUT -p udp -m multiport --sports $UNIQUE_PORTS -s $UNIQUE_IPS -j ACCEPT

# 7) DNS leak prevention (IPv4 DNS)
iptables -A OUTPUT -o tun0 -p udp --dport 53 -d $DNS1 -j ACCEPT
iptables -A OUTPUT -o tun0 -p tcp --dport 53 -d $DNS1 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j DROP
iptables -A OUTPUT -p tcp --dport 53 -j DROP

# 8) Block any other outbound IPv4 traffic that is NOT via tun0 (and not local or Mullvad servers)
iptables -A OUTPUT ! -o tun0 -d 192.168.1.0/24 -j ACCEPT
iptables -A OUTPUT ! -o tun0 -d $UNIQUE_IPS -j ACCEPT
iptables -A OUTPUT ! -o tun0 -j DROP


########## IPv6 ip6tables ##########
# 1) Flush existing IPv6 rules
ip6tables -F
ip6tables -X

# 2) Default DROP for IPv6
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP

# 3) Allow loopback on IPv6
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT

# 4) Allow IPv6 via tun0
ip6tables -A INPUT -i tun0 -j ACCEPT
ip6tables -A OUTPUT -o tun0 -j ACCEPT

# 5) Block all other IPv6 traffic that is NOT via tun0
#    (If your LAN uses IPv6, you may add specific rules for that range,
#     e.g. fe80::/10 for link-local, but typically it is safer to drop all.)
ip6tables -A OUTPUT ! -o tun0 -j DROP
ip6tables -A INPUT ! -i tun0 -j DROP

# If Mullvad provides IPv6 server addresses, you would explicitly allow them here
# For example:
# ip6tables -A OUTPUT -p udp --dport 1300:1302 -d 2620:123:45:: -j ACCEPT
# ip6tables -A INPUT -p udp --sport 1300:1302 -s 2620:123:45:: -j ACCEPT
# (Adjust as needed if remote lines contain IPv6 addresses)

# DNS leak prevention for IPv6:
# If Mullvad offers a known IPv6 DNS, you can allow it specifically via tun0.
# Otherwise, block all DNS queries over IPv6:
ip6tables -A OUTPUT -p udp --dport 53 -j DROP
ip6tables -A OUTPUT -p tcp --dport 53 -j DROP

EOF

chmod +x "$KILL_SWITCH_SCRIPT" || error_exit "Failed to set execute permissions on $KILL_SWITCH_SCRIPT"
log "Kill switch script generated at $KILL_SWITCH_SCRIPT"

# Generate restart.sh script
log "Generating restart.sh script..."
RESTART_SCRIPT="$mullvad_dir/restart.sh"
cat << EOF > "$RESTART_SCRIPT"
#!/bin/bash

systemctl restart "$service_name"
EOF
chmod +x "$RESTART_SCRIPT" || error_exit "Failed to set execute permissions on $RESTART_SCRIPT"
log "Restart script generated at $RESTART_SCRIPT"

# Generate status.sh script
log "Generating status.sh script..."
STATUS_SCRIPT="$mullvad_dir/status.sh"
cat << EOF > "$STATUS_SCRIPT"
#!/bin/bash

systemctl status "$service_name"
curl -s https://am.i.mullvad.net/connected
EOF
chmod +x "$STATUS_SCRIPT" || error_exit "Failed to set execute permissions on $STATUS_SCRIPT"
log "Status script generated at $STATUS_SCRIPT"

# Apply iptables and start service (if --default)
if [[ "$GENERATE_ONLY" == false ]]; then
    # Run the kill-switch.sh to enforce the firewall rules
    log "Running kill-switch.sh script to enforce iptables and ip6tables rules..."
    if [[ -x "$KILL_SWITCH_SCRIPT" ]]; then
        "$KILL_SWITCH_SCRIPT" || error_exit "Kill switch script failed"
    else
        error_exit "Kill switch script not found or not executable at $KILL_SWITCH_SCRIPT"
    fi

    # Save IPv4 iptables
    log "Saving iptables (IPv4) settings..."
    service iptables save || error_exit "Failed to save IPv4 iptables settings"

    # Save IPv6 ip6tables
    log "Saving ip6tables (IPv6) settings..."
    service ip6tables save || error_exit "Failed to save IPv6 ip6tables settings"

    # Enable the iptables and ip6tables services to preserve rules on reboot
    systemctl enable iptables || error_exit "Failed to enable iptables service"
    systemctl enable ip6tables || error_exit "Failed to enable ip6tables service"

    # Finally, start the Mullvad service
    log "Starting Mullvad systemd service..."
    systemctl start "$service_name" || error_exit "Failed to start $service_name"

    # Check Mullvad service status
    log "Checking Mullvad service status..."
    if systemctl is-active --quiet "$service_name"; then
        log "Mullvad service $service_name is running"
    else
        error_exit "Mullvad service $service_name failed to start"
    fi
else
    log "Generate-only mode: Skipping system configuration and service management."
fi

log "Setup completed successfully."
