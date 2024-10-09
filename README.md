# Mullvad VPN Setup Script for CentOS 7

An automated script to configure Mullvad VPN on CentOS 7, complete with a kill switch and utility scripts.

## Features

- **Automated VPN Setup**: Simplifies the Mullvad VPN installation process.
- **Kill Switch**: Generates an `iptables` script to prevent traffic leaks when the VPN is down.
- **Utility Scripts**: Includes `restart.sh` and `status.sh` for managing the VPN connection.
- **Custom DNS Support**: Specify a DNS server via script arguments.

## Requirements

- CentOS 7
- Root access
- Packages:
  - `openvpn`
  - `iptables`
  - `iptables-services`
  - `curl`

Install the required packages:

```bash
sudo yum install -y openvpn iptables iptables-services curl
```

## Setup

1. **Download Mullvad OpenVPN Config Files**:

   - Go to [Mullvad OpenVPN Config](https://mullvad.net/en/account/openvpn-config).
   - Download the configuration ZIP file for your desired location (e.g., `mullvad_openvpn_linux_ch_zrh.zip` for Switzerland).

2. **Extract the Config Files**:

   - Unzip the downloaded file in the current directory. This will create a subdirectory named `mullvad_config_<location>/`.
   - Example:

     ```bash
     unzip mullvad_openvpn_linux_ch_zrh.zip
     ```

     This will create a directory like `mullvad_config_linux_ch_zrh/`.

3. **Place `setup.sh` in the Same Directory**:

   Ensure that the `setup.sh` script is in the same directory as the extracted `mullvad_config_<location>/` folder.

   Directory structure:

   ```
   .
   ├── setup.sh
   ├── mullvad_config_<location>/
       ├── mullvad_<location>.conf
       ├── update-resolv-conf
       ├── mullvad_ca.crt
       ├── mullvad_userpass.txt
   ```

4. **Make `setup.sh` Executable**:

   ```bash
   chmod +x setup.sh
   ```

## Usage

### Display Help

```bash
./setup.sh --help
```

### Full Setup

Run the script with default settings:

```bash
sudo ./setup.sh --default
```

Specify a custom DNS server:

```bash
sudo ./setup.sh --default --dns1=<DNS_SERVER_IP>
```

Example:

```bash
sudo ./setup.sh --default --dns1=8.8.8.8
```

### Generate Scripts Only

To generate the scripts without making system changes:

```bash
./setup.sh --generate-only
```

## Generated Scripts

- **`kill-switch.sh`**: Configures `iptables` rules for the kill switch.
- **`restart.sh`**: Restarts the Mullvad OpenVPN service.
- **`status.sh`**: Checks the VPN connection status.

## Notes

- **Network Interface**: Assumes your network interface is `eth0`. Update `setup.sh` if it's different.
- **VPN Protocol**: Defaults to `udp`. Modify `kill-switch.sh` if using `tcp`.
- **Local Network**: Adjust the subnet in `kill-switch.sh` if necessary.
- **Permissions**: Ensure scripts are executable:

  ```bash
  chmod +x restart.sh status.sh
  chmod +x iptables/kill-switch.sh
  ```

## Troubleshooting

- **Service Issues**: Check the Mullvad configuration and ensure all files are correctly placed.
- **DNS Problems**: Verify the DNS server IP is correct and accessible.
- **Firewall Rules**: Review `kill-switch.sh` if you have connectivity issues.

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Contributions are welcome! Feel free to submit a pull request or open an issue.

---

**Disclaimer**: Use this script at your own risk. Always review scripts before executing them on your system.
