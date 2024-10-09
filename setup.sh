#!/bin/bash

# Mullvad VPN automatic setup script with integrated kill switch and utility scripts generation
# Enhanced with error handling and DNS configuration
# Includes --generate-only, --default, and --dns1=<IP> arguments for flexible operation

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
Mullvad VPN Setup Script

Usage:
  $0 --default [--dns1=<IP>]        Run the full setup (system configurations and script generation)
  $0 --generate-only                Generate the scripts without modifying system configurations
  $0 --help                         Display this help message

Options:
  --dns1=<IP>                       Specify the DNS1 IP address to use (default: 100.64.0.63)

Description:
  This script automates the setup of Mullvad VPN on a CentOS 7 server. It can perform the following actions:

  --default:
    - Stop and disable existing Mullvad OpenVPN services
    - Remove existing OpenVPN configurations in /etc/openvpn/
    - Copy Mullvad configuration files to /etc/openvpn/
    - Enable and start the Mullvad OpenVPN systemd service
    - Update DNS settings in the network configuration
    - Generate the kill-switch.sh, restart.sh, and status.sh scripts
    - Run the kill switch script and save iptables settings

  --generate-only:
    - Generate the kill-switch.sh, restart.sh, and status.sh scripts based on your VPN configuration
    - Does NOT modify system configurations or iptables settings

  --help:
    - Display this help message and exit

Ensure that this script is located in the same directory as your Mullvad configuration files.

EOF
}

# Default DNS1 address
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
    log "Running in generate-only mode: System configurations and iptables will not be modified."
fi

if [[ "$DEFAULT_MODE" == true ]]; then
    log "Running in default mode: Full setup will be performed."
    log "Using DNS1 address: $DNS1"
fi

# Get the directory where the script is located
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Determine the Mullvad directory based on the script's location
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

    # Update DNS1 line in the network configuration
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
    # In generate-only mode, set variables needed for script generation
    # Assume mullvad_conf and service_name based on the configuration directory
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

# Ensure the OpenVPN configuration file exists
if [[ ! -f "$OPENVPN_CONF" ]]; then
    error_exit "OpenVPN configuration file not found at $OPENVPN_CONF"
fi

# Extract remote server IPs and ports from the OpenVPN config
REMOTE_ENTRIES=$(grep '^remote ' "$OPENVPN_CONF" | sed 's/#.*//')  # Remove comments

if [[ -z "$REMOTE_ENTRIES" ]]; then
    error_exit "No remote entries found in $OPENVPN_CONF"
fi

# Initialize arrays
declare -A PORTS
declare -A IPS

# Parse the remote entries
while read -r line; do
    read -a tokens <<< "$line"
    # tokens[0] is 'remote', tokens[1] is IP, tokens[2] is port
    IP="${tokens[1]}"
    PORT="${tokens[2]}"
    # Add to associative arrays to ensure uniqueness
    IPS["$IP"]=1
    PORTS["$PORT"]=1
done <<< "$REMOTE_ENTRIES"

# Create comma-separated lists of unique IPs and ports
UNIQUE_IPS=$(echo "${!IPS[@]}" | tr ' ' ',')
UNIQUE_PORTS=$(echo "${!PORTS[@]}" | tr ' ' ',')

# Generate the kill-switch.sh script
mkdir -p "$(dirname "$KILL_SWITCH_SCRIPT")"

cat << EOF > "$KILL_SWITCH_SCRIPT"
#!/bin/bash

# Clear all existing rules
iptables -F
iptables -X

# Set default policies for all chains to DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow traffic to/from localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow traffic to/from VPN interface (tun0)
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A OUTPUT -o tun0 -j ACCEPT

# Allow outgoing traffic to OpenVPN servers
iptables -A OUTPUT -p udp -m multiport --dports $UNIQUE_PORTS -d $UNIQUE_IPS -j ACCEPT

# Allow incoming traffic from OpenVPN servers
iptables -A INPUT -p udp -m multiport --sports $UNIQUE_PORTS -s $UNIQUE_IPS -j ACCEPT

# Allow traffic from/to local network
iptables -A INPUT -s 192.168.1.0/24 -j ACCEPT
iptables -A OUTPUT -d 192.168.1.0/24 -j ACCEPT
EOF

# Make the kill-switch script executable
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
curl https://am.i.mullvad.net/connected
EOF
chmod +x "$STATUS_SCRIPT" || error_exit "Failed to set execute permissions on $STATUS_SCRIPT"
log "Status script generated at $STATUS_SCRIPT"

if [[ "$GENERATE_ONLY" == false ]]; then
    # Run the kill switch script
    log "Running kill switch script..."
    if [[ -x "$KILL_SWITCH_SCRIPT" ]]; then
        "$KILL_SWITCH_SCRIPT" || error_exit "Kill switch script failed"
    else
        error_exit "Kill switch script not found or not executable at $KILL_SWITCH_SCRIPT"
    fi

    # Save iptables settings
    log "Saving iptables settings..."
    service iptables save || error_exit "Failed to save iptables settings"

    # Start the Mullvad systemd service
    log "Starting Mullvad systemd service..."
    systemctl start "$service_name" || error_exit "Failed to start $service_name"

    # Check the status of the Mullvad service
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

