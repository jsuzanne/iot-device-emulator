# IoT Device Emulator for Palo Alto SD-WAN

A Python-based IoT device emulator designed to test Palo Alto Networks SD-WAN and IoT Security features. Simulates realistic traffic from cameras, sensors, smart home devices, and more.

## Features

- **Realistic IoT Device Simulation**: Emulates 10+ device types (Hikvision cameras, Philips Hue, Xiaomi sensors, Amazon Echo, etc.)
- **Complete DHCP Workflow**: DISCOVER → OFFER → REQUEST → ACK with detailed logging
- **Multi-Protocol Support**: ARP, DHCP, HTTP, HTTPS, MQTT, RTSP, DNS, NTP, mDNS
- **Cloud Traffic**: Generates realistic traffic to vendor-specific cloud servers (Hikvision → Hik-Connect, Xiaomi → Mi Cloud, etc.)
- **Flexible DHCP Modes**: Auto (accept server-assigned IPs) or Static (request specific IPs)
- **JSON Configuration**: Easy device management via configuration file
- **Detailed Logging**: Console + file logging with emoji-rich output

## Use Cases

- Test Palo Alto Networks **IoT Security** module device discovery
- Validate SD-WAN **traffic policies** and QoS
- Simulate IoT network behavior for **security testing**
- Lab environment for **Prisma SD-WAN** (ION devices)

## Requirements

- Python 3.6+
- Scapy library
- Root/sudo privileges (for packet crafting)
- Linux (tested on Ubuntu)

## Installation

Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/iot-device-emulator.git
cd iot-device-emulator
```

Install dependencies
```
sudo pip3 install scapy
```

Make script executable
```bash
chmod +x iot_emulator.py
```

## Quick Start

Run with auto DHCP mode (recommended)
sudo python3 iot_emulator.py -i eth0 --dhcp-mode auto

Run with static IP mode
sudo python3 iot_emulator.py -i ens4 --dhcp-mode static

Run for 5 minutes only
sudo python3 iot_emulator.py -i eth0 -d 300

Check status
sudo python3 iot_emulator.py -s

text

## Configuration

Edit `iot_devices.json` to customize devices:

{
"network": {
"interface": "eth0",
"gateway": "192.168.1.1",
"dhcp_server": "192.168.1.1",
"subnet_mask": "255.255.255.0"
},
"devices": [
{
"id": "camera_01",
"name": "Hikvision DS-2CD2042FWD",
"vendor": "Hikvision",
"type": "security_camera",
"mac": "00:12:34:56:78:01",
"ip_start": "192.168.1.100",
"protocols": ["arp", "dhcp", "http", "rtsp", "cloud", "dns", "ntp"],
"enabled": true,
"traffic_interval": 60
}
]
}

text

## Usage Examples

### Basic Usage

Start emulator on interface ens4
sudo python3 iot_emulator.py -i ens4 --dhcp-mode auto

text

### Monitor Traffic

In another terminal, capture DHCP traffic
sudo tcpdump -i ens4 -vvv port 67 or port 68

Capture all IoT traffic
sudo tcpdump -i ens4 -n

text

### Add New Devices

Add to `iot_devices.json`:

{
"id": "new_device",
"name": "My IoT Device",
"vendor": "VendorName",
"type": "sensor",
"mac": "00:11:22:33:44:55",
"ip_start": "192.168.1.200",
"protocols": ["arp", "dhcp", "mqtt", "cloud"],
"enabled": true,
"traffic_interval": 90
}

text

## DHCP Modes

### Auto Mode (Recommended)
- Devices accept any IP assigned by DHCP server
- Perfect for testing with DHCP ranges (e.g., 192.168.1.180-200)
- Captures OFFER and ACK responses

sudo python3 iot_emulator.py -i eth0 --dhcp-mode auto

text

### Static Mode
- Devices request specific IPs from JSON config (`ip_start` field)
- Useful for controlled IP assignments

sudo python3 iot_emulator.py -i eth0 --dhcp-mode static

text

## Supported Devices

| Vendor | Device Type | Protocols | Cloud Destinations |
|--------|-------------|-----------|-------------------|
| Hikvision | Security Camera | ARP, DHCP, HTTP, RTSP, DNS, NTP | hik-connect.com |
| Dahua | IP Camera | ARP, DHCP, HTTP, RTSP | dahuasecurity.com |
| Philips | Smart Bulb | ARP, DHCP, HTTP | api.meethue.com |
| Xiaomi | Temperature Sensor | ARP, DHCP, MQTT | iot.mi.com |
| Sonoff | Smart Switch | ARP, DHCP, MQTT, HTTP | eu-api.coolkit.cc |
| TP-Link | Smart Plug | ARP, DHCP, HTTP, NTP | wap.tplinkcloud.com |
| Google | Nest Thermostat | ARP, DHCP, HTTP, NTP | home.nest.com |
| Amazon | Echo Dot | ARP, DHCP, HTTP, mDNS, NTP | alexa.amazon.com |
| Meross | Smart Plug | ARP, DHCP, HTTP | iot.meross.com |

## Logging

Logs are written to:
- **Console**: Real-time output with emojis
- **File**: `iot_emulator.log` (detailed debug info)

Example output:

🚀 Starting device: [Hikvision] Hikvision DS-2CD2042FWD (192.168.1.180) [DHCP mode: auto]
🔄 camera_01: Starting DHCP sequence (mode: auto)...
📤 camera_01: Sending DHCP DISCOVER (xid: 0x3bbff79e, MAC: 00:12:34:56:78:01)
⏳ camera_01: Waiting for DHCP OFFER (timeout: 3s)...
✅ camera_01: Received DHCP OFFER from 192.168.1.1
└─ Offered IP: 192.168.1.180
└─ Server ID: 192.168.1.1
└─ Lease Time: 86400s
📤 camera_01: Sending DHCP REQUEST for offered IP 192.168.1.180
✅ camera_01: Received DHCP ACK from 192.168.1.1
✅ camera_01: DHCP sequence completed (current IP: 192.168.1.180)
☁️ Cloud HTTPS from camera_01 to 47.88.59.64:443

text

## Testing with Palo Alto ION v3102

1. **Configure ION DHCP Server**:
   - Enable DHCP relay or server on LAN interface
   - Set range (e.g., 192.168.207.180-200)

2. **Enable Device-ID in Prisma SD-WAN**:
   - Navigate to ION settings
   - Enable "Device ID" feature
   - Configure Strata Logging Service

3. **Run Emulator**:
sudo python3 iot_emulator.py -i ens4 --dhcp-mode auto

text

4. **Verify in Strata Cloud Manager**:
- Check **IoT Security** dashboard (5-10 min delay)
- Devices should appear with classifications (camera, sensor, etc.)
- Review security policies and recommendations

## Command-Line Options

usage: iot_emulator.py [-h] [-c CONFIG] [-i INTERFACE] [--dhcp-mode {auto,static}]
[-d DURATION] [-s]

Options:
-h, --help Show help message
-c CONFIG Path to config file (default: iot_devices.json)
-i INTERFACE Network interface (default: eth0)
--dhcp-mode {auto,static} DHCP mode (default: auto)
-d DURATION Run duration in seconds (default: infinite)
-s, --status Print device status and exit

text

## Troubleshooting

### No DHCP responses
- Check DHCP server is running on gateway
- Verify interface name (`ip link show`)
- Ensure no firewall blocking DHCP (ports 67/68)

### Permission errors
- Script requires root: `sudo python3 iot_emulator.py`
- Check Scapy is installed: `pip3 list | grep scapy`

### Devices not detected by ION
- Verify ION can see DHCP traffic: `tcpdump -i <interface> port 67`
- Check Device-ID is enabled in Prisma SD-WAN
- Wait 5-10 minutes for IoT Security to classify devices

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details

## Author

Created for testing Palo Alto Networks SD-WAN and IoT Security solutions.

## Acknowledgments

- Palo Alto Networks for IoT Security inspiration
- Scapy library for packet crafting capabilities
- Real IoT device behavior research

## Disclaimer

This tool is for **testing and educational purposes only**. Use only in authorized lab environments. Do not use on production networks without permission.

---

**⭐ If you find this project useful, please star it on GitHub!**
