#!/usr/bin/env python3
"""
IoT Device Emulator for Palo Alto SD-WAN/IoT Security Lab
Generates ARP, DHCP, MQTT, HTTP, RTSP traffic to simulate real IoT devices
"""

import json
import sys
import time
import threading
import logging
import argparse
import random
import warnings
from datetime import datetime
from pathlib import Path
import os

# Suppress Scapy import errors by redirecting stderr temporarily
_original_stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')

try:
    from scapy.all import (
        Ether, IP, UDP, TCP, DHCP, ARP, DNS, DNSQR, Raw, BOOTP,
        sendp, send, conf, sniff, get_if_hwaddr
    )
finally:
    # Always restore stderr, even if import fails
    sys.stderr.close()
    sys.stderr = _original_stderr

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iot_emulator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class IoTDevice:
    """Base class for IoT device simulation"""
    
    # Cloud destinations per vendor (real public IPs)
    CLOUD_DESTINATIONS = {
        "Hikvision": {
            "servers": ["47.88.59.64", "39.107.142.200"],
            "domains": ["hik-connect.com", "hikvision.com"]
        },
        "Dahua": {
            "servers": ["47.90.123.45"],
            "domains": ["dahuasecurity.com", "p2p.dahuasecurity.com"]
        },
        "Philips": {
            "servers": ["192.229.211.108"],
            "domains": ["api.meethue.com", "firmware.meethue.com"]
        },
        "Xiaomi": {
            "servers": ["47.88.62.181", "120.92.65.244"],
            "domains": ["iot.mi.com", "api.io.mi.com"]
        },
        "Amazon": {
            "servers": ["52.94.236.248", "54.239.31.128"],
            "domains": ["alexa.amazon.com", "device-metrics-us.amazon.com"]
        },
        "Google": {
            "servers": ["216.58.213.206", "172.217.168.46"],
            "domains": ["home.nest.com", "googlehomeservices-pa.googleapis.com"]
        },
        "Sonoff": {
            "servers": ["18.185.104.23", "52.28.132.157"],
            "domains": ["eu-api.coolkit.cc", "eu-disp.coolkit.cc"]
        },
        "TP-Link": {
            "servers": ["52.41.56.200", "54.148.220.147"],
            "domains": ["wap.tplinkcloud.com", "use1-api.tplinkra.com"]
        },
        "Meross": {
            "servers": ["13.36.125.34"],
            "domains": ["iot.meross.com", "mqtt.meross.com"]
        }
    }
    
    # Common public services
    PUBLIC_SERVICES = {
        "ntp": ["129.6.15.28", "216.239.35.0"],
        "dns": ["8.8.8.8", "1.1.1.1"],
    }
    
    def __init__(self, device_config, interface="eth0", dhcp_mode="auto"):
        self.id = device_config.get("id")
        self.name = device_config.get("name")
        self.vendor = device_config.get("vendor")
        self.device_type = device_config.get("type")
        self.mac = device_config.get("mac")
        self.ip_static = device_config.get("ip_start")
        self.ip = self.ip_static
        self.protocols = device_config.get("protocols", [])
        self.enabled = device_config.get("enabled", True)
        self.traffic_interval = device_config.get("traffic_interval", 60)
        self.mqtt_topic = device_config.get("mqtt_topic")
        self.interface = interface
        self.gateway = "192.168.207.1"
        self.running = False
        self.dhcp_xid = random.randint(1, 0xFFFFFFFF)
        self.dhcp_offered_ip = None
        self.dhcp_server_ip = None
        self.dhcp_mode = dhcp_mode
        
    def __repr__(self):
        return f"[{self.vendor}] {self.name} ({self.ip})"
    
    def start(self):
        """Start device emulation threads"""
        if not self.enabled:
            logger.warning(f"Device {self} is disabled, skipping")
            return
        
        self.running = True
        logger.info(f"🚀 Starting device: {self} [DHCP mode: {self.dhcp_mode}]")
        
        # Start with DHCP to get IP (if dhcp in protocols)
        if "dhcp" in self.protocols:
            threading.Thread(target=self.do_dhcp_sequence, daemon=True).start()
            time.sleep(2)
        
        # Start protocol-specific threads
        for protocol in self.protocols:
            if protocol != "dhcp":
                thread = threading.Thread(
                    target=self._protocol_handler,
                    args=(protocol,),
                    daemon=True
                )
                thread.start()
        
        # DHCP renewal thread (periodic)
        if "dhcp" in self.protocols:
            thread = threading.Thread(target=self.dhcp_renewal_loop, daemon=True)
            thread.start()
    
    def stop(self):
        """Stop device emulation"""
        self.running = False
        logger.info(f"⏹️  Stopped device: {self}")
    
    def _protocol_handler(self, protocol):
        """Route to protocol handler"""
        handlers = {
            "arp": self.send_arp,
            "http": self.send_http,
            "mqtt": self.send_mqtt,
            "rtsp": self.send_rtsp,
            "mdns": self.send_mdns,
            "cloud": self.send_cloud_traffic,
            "dns": self.send_dns,
            "ntp": self.send_ntp,
        }
        
        handler = handlers.get(protocol)
        if handler:
            handler()
        else:
            logger.warning(f"Unknown protocol: {protocol}")
    
    def parse_dhcp_options(self, packet):
        """Parse DHCP options and return as dict"""
        options = {}
        if DHCP in packet:
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and len(opt) == 2:
                    options[opt[0]] = opt[1]
        return options
    
    def do_dhcp_sequence(self):
        """Perform complete DHCP sequence: Discover -> Offer -> Request -> ACK"""
        try:
            logger.info(f"🔄 {self.id}: Starting DHCP sequence (mode: {self.dhcp_mode})...")
            
            # Step 1: Send DHCP Discover
            self.dhcp_xid = random.randint(1, 0xFFFFFFFF)
            
            discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac) / \
                       IP(src="0.0.0.0", dst="255.255.255.255") / \
                       UDP(sport=68, dport=67) / \
                       BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.dhcp_xid) / \
                       DHCP(options=[
                           ("message-type", "discover"),
                           ("hostname", self.name.encode()),
                           ("param_req_list", [1, 3, 6, 15]),
                           ("end")
                       ])
            
            logger.info(f"📤 {self.id}: Sending DHCP DISCOVER (xid: {hex(self.dhcp_xid)}, MAC: {self.mac})")
            sendp(discover, iface=self.interface, verbose=0)
            
            # Step 2: Wait and capture DHCP OFFER
            logger.info(f"⏳ {self.id}: Waiting for DHCP OFFER (timeout: 3s)...")
            
            try:
                def dhcp_filter(pkt):
                    if DHCP in pkt and BOOTP in pkt:
                        if pkt[BOOTP].xid == self.dhcp_xid:
                            return True
                    return False
                
                packets = sniff(
                    iface=self.interface,
                    lfilter=dhcp_filter,
                    timeout=3,
                    count=1,
                    store=1
                )
                
                if packets:
                    offer_pkt = packets[0]
                    options = self.parse_dhcp_options(offer_pkt)
                    msg_type = options.get('message-type')
                    
                    if msg_type == 2:  # OFFER
                        self.dhcp_offered_ip = offer_pkt[BOOTP].yiaddr
                        self.dhcp_server_ip = offer_pkt[BOOTP].siaddr or offer_pkt[IP].src
                        
                        logger.info(f"✅ {self.id}: Received DHCP OFFER from {self.dhcp_server_ip}")
                        logger.info(f"   └─ Offered IP: {self.dhcp_offered_ip}")
                        logger.info(f"   └─ Server ID: {options.get('server_id', 'N/A')}")
                        logger.info(f"   └─ Subnet Mask: {options.get('subnet_mask', 'N/A')}")
                        logger.info(f"   └─ Router: {options.get('router', 'N/A')}")
                        logger.info(f"   └─ DNS: {options.get('name_server', 'N/A')}")
                        logger.info(f"   └─ Lease Time: {options.get('lease_time', 'N/A')}s")
                    else:
                        logger.warning(f"⚠️  {self.id}: Received DHCP packet but not OFFER (type: {msg_type})")
                else:
                    logger.warning(f"⚠️  {self.id}: No DHCP OFFER received (timeout)")
                    
            except Exception as e:
                logger.warning(f"⚠️  {self.id}: Could not capture DHCP OFFER: {e}")
            
            time.sleep(0.5)
            
            # Step 3: Send DHCP Request
            dhcp_options = [("message-type", "request")]
            
            if self.dhcp_mode == "static" and self.ip_static:
                dhcp_options.append(("requested_addr", self.ip_static))
                logger.info(f"📤 {self.id}: Sending DHCP REQUEST for static IP {self.ip_static}")
            elif self.dhcp_offered_ip:
                dhcp_options.append(("requested_addr", self.dhcp_offered_ip))
                self.ip = self.dhcp_offered_ip
                logger.info(f"📤 {self.id}: Sending DHCP REQUEST for offered IP {self.dhcp_offered_ip}")
            else:
                logger.info(f"📤 {self.id}: Sending DHCP REQUEST (accepting any IP from server)")
            
            if self.dhcp_server_ip:
                dhcp_options.append(("server_id", self.dhcp_server_ip))
            else:
                dhcp_options.append(("server_id", self.gateway))
            
            dhcp_options.extend([
                ("hostname", self.name.encode()),
                ("param_req_list", [1, 3, 6, 15]),
                ("end")
            ])
            
            request = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac) / \
                      IP(src="0.0.0.0", dst="255.255.255.255") / \
                      UDP(sport=68, dport=67) / \
                      BOOTP(chaddr=bytes.fromhex(self.mac.replace(':', '')), xid=self.dhcp_xid) / \
                      DHCP(options=dhcp_options)
            
            sendp(request, iface=self.interface, verbose=0)
            
            # Step 4: Wait and capture DHCP ACK
            logger.info(f"⏳ {self.id}: Waiting for DHCP ACK (timeout: 3s)...")
            
            try:
                packets = sniff(
                    iface=self.interface,
                    lfilter=dhcp_filter,
                    timeout=3,
                    count=1,
                    store=1
                )
                
                if packets:
                    ack_pkt = packets[0]
                    options = self.parse_dhcp_options(ack_pkt)
                    msg_type = options.get('message-type')
                    
                    if msg_type == 5:  # ACK
                        assigned_ip = ack_pkt[BOOTP].yiaddr
                        self.ip = assigned_ip
                        
                        logger.info(f"✅ {self.id}: Received DHCP ACK from {ack_pkt[IP].src}")
                        logger.info(f"   └─ Assigned IP: {assigned_ip}")
                        logger.info(f"   └─ Server ID: {options.get('server_id', 'N/A')}")
                        logger.info(f"   └─ Subnet Mask: {options.get('subnet_mask', 'N/A')}")
                        logger.info(f"   └─ Router: {options.get('router', 'N/A')}")
                        logger.info(f"   └─ DNS: {options.get('name_server', 'N/A')}")
                        logger.info(f"   └─ Lease Time: {options.get('lease_time', 'N/A')}s")
                    elif msg_type == 6:  # NAK
                        logger.error(f"❌ {self.id}: Received DHCP NAK - request rejected by server")
                    else:
                        logger.warning(f"⚠️  {self.id}: Received DHCP packet but not ACK (type: {msg_type})")
                else:
                    logger.warning(f"⚠️  {self.id}: No DHCP ACK received (timeout) - using fallback IP {self.ip}")
                    
            except Exception as e:
                logger.warning(f"⚠️  {self.id}: Could not capture DHCP ACK: {e}")
            
            logger.info(f"✅ {self.id}: DHCP sequence completed (current IP: {self.ip})")
            
        except Exception as e:
            logger.error(f"❌ DHCP sequence error for {self.id}: {e}", exc_info=True)
    
    def dhcp_renewal_loop(self):
        """Periodic DHCP renewal"""
        logger.debug(f"🔄 DHCP renewal thread started for {self.id}")
        
        time.sleep(self.traffic_interval * 5)
        
        while self.running:
            try:
                logger.info(f"🔄 {self.id}: Performing DHCP renewal...")
                self.do_dhcp_sequence()
                
            except Exception as e:
                logger.error(f"❌ DHCP renewal error for {self.id}: {e}")
            
            time.sleep(self.traffic_interval * 5)
    
    def send_arp(self):
        """Send ARP requests (device discovery)"""
        logger.debug(f"🔍 ARP thread started for {self.id}")
        
        while self.running:
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac) / \
                      ARP(op="who-has", 
                          pdst=self.gateway, 
                          hwsrc=self.mac, 
                          psrc=self.ip)
                
                sendp(pkt, iface=self.interface, verbose=0)
                logger.debug(f"📤 ARP request from {self.id}: {self.ip} ({self.mac})")
                
            except Exception as e:
                logger.error(f"❌ ARP error for {self.id}: {e}")
            
            time.sleep(self.traffic_interval)
    
    def send_http(self):
        """Send HTTP requests (configuration/status check)"""
        logger.debug(f"🌐 HTTP thread started for {self.id}")
        
        while self.running:
            try:
                pkt = IP(src=self.ip, dst=self.gateway) / \
                      TCP(dport=80, flags="S")
                
                send(pkt, verbose=0)
                logger.debug(f"📤 HTTP SYN from {self.id} to {self.gateway}:80")
                
            except Exception as e:
                logger.error(f"❌ HTTP error for {self.id}: {e}")
            
            time.sleep(self.traffic_interval)
    
    def send_mqtt(self):
        """Send MQTT publish packets (for sensors)"""
        logger.debug(f"💬 MQTT thread started for {self.id}")
        
        mqtt_broker = "192.168.207.150"
        
        while self.running:
            try:
                pkt = IP(src=self.ip, dst=mqtt_broker) / \
                      TCP(dport=1883, flags="S")
                
                send(pkt, verbose=0)
                logger.debug(f"📤 MQTT Connect from {self.id} to {mqtt_broker}:1883")
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"❌ MQTT error for {self.id}: {e}")
            
            time.sleep(self.traffic_interval)
    
    def send_rtsp(self):
        """Send RTSP requests (for cameras)"""
        logger.debug(f"🎥 RTSP thread started for {self.id}")
        
        while self.running:
            try:
                pkt = IP(src=self.ip, dst=self.gateway) / \
                      TCP(dport=554, flags="S")
                
                send(pkt, verbose=0)
                logger.debug(f"📤 RTSP SYN from {self.id} to {self.gateway}:554")
                
            except Exception as e:
                logger.error(f"❌ RTSP error for {self.id}: {e}")
            
            time.sleep(self.traffic_interval)
    
    def send_mdns(self):
        """Send mDNS requests (for discovery)"""
        logger.debug(f"🔎 mDNS thread started for {self.id}")
        
        while self.running:
            try:
                pkt = IP(src=self.ip, dst="224.0.0.251") / \
                      UDP(sport=5353, dport=5353)
                
                send(pkt, verbose=0)
                logger.debug(f"📤 mDNS query from {self.id}")
                
            except Exception as e:
                logger.error(f"❌ mDNS error for {self.id}: {e}")
            
            time.sleep(self.traffic_interval * 3)
    
    def send_cloud_traffic(self):
        """Send HTTPS traffic to vendor cloud servers"""
        logger.debug(f"☁️  Cloud traffic thread started for {self.id}")
        
        cloud_config = self.CLOUD_DESTINATIONS.get(self.vendor, {
            "servers": ["8.8.8.8"],
            "domains": []
        })
        
        servers = cloud_config.get("servers", [])
        
        while self.running:
            try:
                for server in servers:
                    pkt = IP(src=self.ip, dst=server) / \
                          TCP(dport=443, flags="S")
                    
                    send(pkt, verbose=0)
                    logger.info(f"☁️  Cloud HTTPS from {self.id} to {server}:443")
                    
                    time.sleep(2)
                    
                    pkt_http = IP(src=self.ip, dst=server) / \
                               TCP(dport=80, flags="S")
                    
                    send(pkt_http, verbose=0)
                    logger.info(f"☁️  Cloud HTTP from {self.id} to {server}:80")
                    
                    time.sleep(3)
                
            except Exception as e:
                logger.error(f"❌ Cloud traffic error for {self.id}: {e}")
            
            time.sleep(self.traffic_interval * 2)
    
    def send_dns(self):
        """Send DNS queries to public resolvers"""
        logger.debug(f"🌐 DNS thread started for {self.id}")
        
        cloud_config = self.CLOUD_DESTINATIONS.get(self.vendor, {"domains": []})
        domains = cloud_config.get("domains", ["www.google.com"])
        
        dns_servers = self.PUBLIC_SERVICES["dns"]
        
        while self.running:
            try:
                for domain in domains:
                    for dns_server in dns_servers:
                        pkt = IP(src=self.ip, dst=dns_server) / \
                              UDP(sport=53000, dport=53) / \
                              DNS(rd=1, qd=DNSQR(qname=domain))
                        
                        send(pkt, verbose=0)
                        logger.info(f"🌐 DNS query from {self.id}: {domain} → {dns_server}")
                        
                        time.sleep(1)
                
            except Exception as e:
                logger.error(f"❌ DNS error for {self.id}: {e}")
            
            time.sleep(self.traffic_interval * 3)
    
    def send_ntp(self):
        """Send NTP time sync requests"""
        logger.debug(f"🕐 NTP thread started for {self.id}")
        
        ntp_servers = self.PUBLIC_SERVICES["ntp"]
        
        while self.running:
            try:
                for ntp_server in ntp_servers:
                    pkt = IP(src=self.ip, dst=ntp_server) / \
                          UDP(sport=123, dport=123)
                    
                    send(pkt, verbose=0)
                    logger.info(f"🕐 NTP request from {self.id} to {ntp_server}")
                    
                    time.sleep(2)
                
            except Exception as e:
                logger.error(f"❌ NTP error for {self.id}: {e}")
            
            time.sleep(self.traffic_interval * 5)


class IoTEmulator:
    """Main emulator controller"""
    
    def __init__(self, config_file, interface="eth0", dhcp_mode="auto"):
        self.config_file = Path(config_file)
        self.interface_cli = interface
        self.interface = interface
        self.dhcp_mode = dhcp_mode
        self.devices = []
        self.threads = []
        
        if conf.route is None:
            logger.error("⚠️  Scapy requires root/sudo permissions!")
            sys.exit(1)
        
        logger.info("=" * 60)
        logger.info("🚀 IoT Emulator for Palo Alto SD-WAN/IoT Security Lab")
        logger.info(f"   DHCP Mode: {dhcp_mode.upper()}")
        logger.info("=" * 60)
    
    def load_config(self):
        """Load device configuration from JSON"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            logger.info(f"✅ Loaded config from {self.config_file}")
            
            network = config.get("network", {})
            
            if self.interface_cli == "eth0" and "interface" in network:
                self.interface = network.get("interface")
                logger.info(f"📡 Using interface from config: {self.interface}")
            else:
                logger.info(f"📡 Using interface from CLI: {self.interface}")
            
            self.gateway = network.get("gateway", "192.168.207.1")
            
            for device_config in config.get("devices", []):
                device = IoTDevice(device_config, interface=self.interface, dhcp_mode=self.dhcp_mode)
                device.gateway = self.gateway
                self.devices.append(device)
            
            logger.info(f"✅ Loaded {len(self.devices)} devices")
            for device in self.devices:
                status = "✅ enabled" if device.enabled else "⏸️  disabled"
                logger.info(f"   {device} - {status}")
            
        except FileNotFoundError:
            logger.error(f"❌ Config file not found: {self.config_file}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error(f"❌ Invalid JSON in config: {e}")
            sys.exit(1)
    
    def start_all(self):
        """Start all enabled devices"""
        logger.info("🚀 Starting all devices...")
        
        for device in self.devices:
            if device.enabled:
                device.start()
                time.sleep(0.5)
        
        logger.info(f"✅ All {len([d for d in self.devices if d.enabled])} devices started")
    
    def stop_all(self):
        """Stop all devices"""
        logger.info("⏹️  Stopping all devices...")
        
        for device in self.devices:
            device.stop()
        
        logger.info("✅ All devices stopped")
    
    def print_status(self):
        """Print current status"""
        print("\n" + "=" * 60)
        print(f"📊 IoT Emulator Status - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   DHCP Mode: {self.dhcp_mode.upper()}")
        print("=" * 60)
        
        for device in self.devices:
            status = "🟢 RUNNING" if device.running else "🔴 STOPPED"
            protocols = ", ".join(device.protocols)
            print(f"{status} | {str(device):45} | {protocols}")
        
        print("=" * 60 + "\n")
    
    def run(self, duration=None):
        """Run emulator"""
        try:
            self.load_config()
            self.start_all()
            
            if duration:
                logger.info(f"⏱️  Running for {duration} seconds...")
                time.sleep(duration)
                self.stop_all()
            else:
                logger.info("✅ Emulator running (Ctrl+C to stop)...")
                
                try:
                    while True:
                        time.sleep(60)
                        self.print_status()
                except KeyboardInterrupt:
                    logger.info("\n🛑 Interrupt received, stopping...")
                    self.stop_all()
        
        except KeyboardInterrupt:
            logger.info("\n🛑 Interrupt received, stopping...")
            self.stop_all()
        except Exception as e:
            logger.error(f"❌ Fatal error: {e}", exc_info=True)
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="IoT Device Emulator for Palo Alto SD-WAN/IoT Security Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DHCP Modes:
  auto   - Accept any IP assigned by DHCP server (recommended)
  static - Request specific IP from JSON config (ip_start field)

Examples:
  sudo python3 iot_emulator.py -i ens4 --dhcp-mode auto
  sudo python3 iot_emulator.py -i ens4 --dhcp-mode static
        """
    )
    parser.add_argument(
        "-c", "--config",
        default="iot_devices.json",
        help="Path to device configuration file (default: iot_devices.json)"
    )
    parser.add_argument(
        "-i", "--interface",
        default="eth0",
        help="Network interface to use (default: eth0)"
    )
    parser.add_argument(
        "--dhcp-mode",
        choices=["auto", "static"],
        default="auto",
        help="DHCP mode: 'auto' to accept server-assigned IPs, 'static' to request specific IPs from config (default: auto)"
    )
    parser.add_argument(
        "-d", "--duration",
        type=int,
        help="Run duration in seconds (default: infinite)"
    )
    parser.add_argument(
        "-s", "--status",
        action="store_true",
        help="Print status and exit"
    )
    
    args = parser.parse_args()
    
    emulator = IoTEmulator(args.config, interface=args.interface, dhcp_mode=args.dhcp_mode)
    
    if args.status:
        emulator.load_config()
        emulator.print_status()
    else:
        emulator.run(duration=args.duration)


if __name__ == "__main__":
    main()

