import json
import csv
from pathlib import Path

new_cases = [
    {
        "Cases": 31,
        "symptom": "PC0 obtains an IP address via DHCP and can ping the default gateway and external public IPs (e.g., 8.8.8.8), but cannot browse websites using domain names (e.g., www.example.com).",
        "outputs": "PC0> ipconfig /all\nFastEthernet0 Connection:\n   IPv4 Address....................: 192.168.10.50\n   Subnet Mask.....................: 255.255.255.0\n   Default Gateway.................: 192.168.10.1\n   DNS Server......................: 192.168.10.254\n\nRouter0# show running-config | section ip dhcp pool\nip dhcp pool LAN_POOL\n   network 192.168.10.0 255.255.255.0\n   default-router 192.168.10.1\n   dns-server 192.168.10.254\n\nRouter0# show ip interface brief | include 192.168.10\nGigabitEthernet0/0/0       192.168.10.1    YES manual up                    up\n\nRouter0# ping 192.168.10.254\nType escape sequence to abort.\nSending 5, 100-byte ICMP Echos to 192.168.10.254, timeout is 2 seconds:\n.....\nSuccess rate is 0 percent (0/5)",
        "expected fault": "DHCP server is advertising an incorrect or unreachable DNS server address (192.168.10.254) in its DHCP pool configuration.",
        "OSI Layer": "Layer 7",
        "Concept": "DHCP / DNS Mismatch",
        "severity": "High"
    },
    {
        "Cases": 32,
        "symptom": "Switch0 is functioning normally and traffic flows between VLANs, but network administrators cannot telnet or SSH to the switch management IP (192.168.99.2) from another subnet.",
        "outputs": "Switch0# show ip interface brief\nInterface              IP-Address      OK? Method Status                Protocol\nVlan1                  unassigned      YES unset  up                    up\nVlan99                 192.168.99.2    YES manual administratively down down\nFastEthernet0/1        unassigned      YES unset  up                    up\nFastEthernet0/2        unassigned      YES unset  up                    up\n\nSwitch0# show running-config interface vlan 99\nBuilding configuration...\nCurrent configuration : 72 bytes\n!\ninterface Vlan99\n ip address 192.168.99.2 255.255.255.0\n shutdown\nend",
        "expected fault": "Switch virtual interface (SVI) for the management VLAN (Vlan99) is administratively down (shutdown).",
        "OSI Layer": "Layer 3 / Layer 2",
        "Concept": "VLANs / SVI Down",
        "severity": "Medium"
    },
    {
        "Cases": 33,
        "symptom": "A host (PC0) in the sales department is connected to Switch port FastEthernet0/10. It cannot reach the sales gateway (192.168.10.1) or obtain a DHCP address. Pings to 192.168.10.1 fail.",
        "outputs": "Switch0# show mac address-table interface fa0/10\n          Mac Address Table\n-------------------------------------------\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n  20    0060.2f2a.1111    DYNAMIC     Fa0/10\n\nSwitch0# show running-config interface fa0/10\ninterface FastEthernet0/10\n switchport access vlan 20\n switchport mode access\nend\n\nSwitch0# show vlan brief\nVLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n1    default                          active    Fa0/1, Fa0/2, Fa0/3\n10   Sales                            active    Fa0/4, Fa0/5\n20   Marketing                        active    Fa0/10, Fa0/11",
        "expected fault": "Switch access port FastEthernet0/10 is assigned to the wrong VLAN (VLAN 20/Marketing) instead of Vlan 10/Sales.",
        "OSI Layer": "Layer 2",
        "Concept": "Switchport VLAN Assignment",
        "severity": "High"
    },
    {
        "Cases": 34,
        "symptom": "Router0 can ping its adjacent neighbors, but remote networks do not receive OSPF routes for the LAN network (192.168.10.0/24) connected to Router0's GigabitEthernet0/0/1 interface.",
        "outputs": "Router0# show ip route ospf\n(No routes displayed)\n\nRouter0# show running-config | section router ospf\nrouter ospf 1\n router-id 1.1.1.1\n network 10.1.1.0 0.0.0.3 area 0\n\nRouter0# show ip interface brief\nInterface                  IP-Address      OK? Method Status                Protocol\nGigabitEthernet0/0/0       10.1.1.1        YES manual up                    up\nGigabitEthernet0/0/1       192.168.10.1    YES manual up                    up",
        "expected fault": "Router0's OSPF process configuration is missing the network statement for the LAN subnet (192.168.10.0/24), so this network is not being advertised.",
        "OSI Layer": "Layer 3",
        "Concept": "OSPF / Missing Network Statement",
        "severity": "High"
    },
    {
        "Cases": 35,
        "symptom": "The first host on the LAN successfully connects to the Internet, but all subsequent hosts are unable to connect. Pings from host 2 to public IP addresses fail.",
        "outputs": "Router0# show ip nat translations\nPro  Inside global     Inside local       Outside local      Outside global\nicmp 203.0.113.10:1024 192.168.1.10:1024  8.8.8.8:1024       8.8.8.8:1024\n\nRouter0# show running-config | include ip nat inside source\nip nat inside source list 1 interface GigabitEthernet0/0/0\n\nRouter0# show access-lists 1\nStandard IP access list 1\n    10 permit 192.168.1.0 0.0.0.255",
        "expected fault": "Dynamic NAT configuration is missing the 'overload' keyword at the end of the source mapping statement, preventing multiple private hosts from sharing the single public WAN IP.",
        "OSI Layer": "Layer 3",
        "Concept": "PAT / Missing Overload",
        "severity": "High"
    },
    {
        "Cases": 36,
        "symptom": "Newly connected PCs in the training room fail to get an IP address via DHCP and fallback to APIPA addresses (169.254.x.x), while older PCs continue to work fine.",
        "outputs": "Router0# show ip dhcp conflict\n(No conflicts found)\n\nRouter0# show ip dhcp pool LAN_POOL\nPool LAN_POOL :\n Utilization mark (30/30)\n Current index 192.168.1.30\n IP address range 192.168.1.10 to 192.168.1.30\n Leased addresses 21\n Pending addresses 0\n Declined addresses 0\n\nRouter0# show running-config | section ip dhcp pool\nip dhcp pool LAN_POOL\n   network 192.168.1.0 255.255.255.0\n   default-router 192.168.1.1\n   dns-server 8.8.8.8",
        "expected fault": "The DHCP address pool is exhausted because the configured lease range is too small (only 21 addresses) for the number of devices in the training room.",
        "OSI Layer": "Layer 7 / Layer 3",
        "Concept": "DHCP / Pool Exhaustion",
        "severity": "High"
    },
    {
        "Cases": 37,
        "symptom": "Network administrators can ping and manage Switch0 from the local management VLAN (VLAN 99), but pings and SSH connections from the IT office in a different subnet (VLAN 10) time out.",
        "outputs": "Switch0# show running-config | include ip default-gateway\n(No output returned)\n\nSwitch0# show ip interface brief | include Vlan\nVlan99                 192.168.99.10   YES manual up                    up\n\nSwitch0# ping 192.168.10.50\nType escape sequence to abort.\nSending 5, 100-byte ICMP Echos to 192.168.10.50, timeout is 2 seconds:\n.....\nSuccess rate is 0 percent (0/5)",
        "expected fault": "Switch0 is missing the 'ip default-gateway' command, preventing it from sending return traffic back to managing stations located in other subnets.",
        "OSI Layer": "Layer 3",
        "Concept": "Gateway / Switch Management",
        "severity": "Medium"
    },
    {
        "Cases": 38,
        "symptom": "Wireless clients can see and associate with the guest SSID \"Staff_WiFi\" successfully, but they are unable to access any network resources. Checking their network status shows they did not get an IP address (status is 0.0.0.0).",
        "outputs": "Wireless-Client-1> ipconfig\n   IPv4 Address....................: 0.0.0.0\n   Subnet Mask.....................: 0.0.0.0\n   Default Gateway.................: 0.0.0.0\n\nWireless_Router# show running-config | include dhcp\nno ip dhcp server\n\nWireless_Router# show ip interface brief\nInterface                  IP-Address      OK? Method Status                Protocol\nVlan1                      192.168.50.1    YES manual up                    up",
        "expected fault": "The DHCP server on the wireless router's LAN interface is disabled, preventing wireless clients from acquiring IP addresses.",
        "OSI Layer": "Layer 3 / Layer 2",
        "Concept": "Wireless / DHCP Disabled",
        "severity": "High"
    },
    {
        "Cases": 39,
        "symptom": "A new office laptop fails to connect to the corporate Wi-Fi network. The status remains \"Connecting...\" or fails with a security mismatch error.",
        "outputs": "Laptop0# show wireless-connection interface wlan0\nSSID: Corp_WiFi\nSecurity: WPA2-Personal\nAuthentication: Failed (Authentication Timeout/Key Mismatch)\n\nAP0# show running-config | section dot11 ssid\ndot11 ssid Corp_WiFi\n   authentication open\n   authentication key-management wpa version 2\n   wpa-psk ascii 0 SecretPassword123\n\nLaptop0# show running-config interface wlan0\ninterface Dot11Radio0\n   ssid Corp_WiFi\n   wpa-psk ascii WrongPassword123",
        "expected fault": "Mismatched WPA2 pre-shared key (passphrase mismatch) configured on the wireless client compared to the access point's security settings.",
        "OSI Layer": "Layer 2 / Layer 1",
        "Concept": "Wireless / Security Mismatch",
        "severity": "High"
    },
    {
        "Cases": 40,
        "symptom": "The network engineer configured a standard ACL to block a host (192.168.1.10) from accessing the internet, but now all hosts in the subnet (192.168.1.0/24) are blocked from accessing the internet.",
        "outputs": "Router0# show access-lists 10\nStandard IP access list 10\n    10 deny any\n    20 permit 192.168.1.0 0.0.0.255\n\nRouter0# show ip interface g0/0/0\nGigabitEthernet0/0/0 is up, line protocol is up\n  Internet address is 203.0.113.2/30\n  Outgoing access list is 10",
        "expected fault": "The standard ACL has a 'deny any' rule placed at the top (sequence 10), which matches all traffic and prevents the subsequent 'permit' rule from being evaluated.",
        "OSI Layer": "Layer 3",
        "Concept": "ACL Rule Order",
        "severity": "High"
    }
]

# Update cases.json
json_path = Path("cases.json")
if json_path.exists():
    with open(json_path, "r", encoding="utf-8") as f:
        cases = json.load(f)
    
    # Check if cases are already added to prevent duplicates
    existing_cases = {c.get("Cases") for c in cases}
    added_count = 0
    for nc in new_cases:
        if nc["Cases"] not in existing_cases:
            cases.append(nc)
            added_count += 1
            
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(cases, f, indent=2, ensure_ascii=False)
    print(f"Added {added_count} cases to cases.json. Total cases: {len(cases)}")

# Update cases.csv
csv_path = Path("cases.csv")
if csv_path.exists():
    # Read existing cases in CSV to check for duplicates
    existing_csv_cases = set()
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if row:
                existing_csv_cases.add(int(row[0]))
                
    added_csv_count = 0
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for nc in new_cases:
            if nc["Cases"] not in existing_csv_cases:
                writer.writerow([
                    nc["Cases"],
                    nc["symptom"],
                    nc["outputs"],
                    nc["expected fault"],
                    nc["OSI Layer"],
                    nc["Concept"],
                    nc["severity"]
                ])
                added_csv_count += 1
    print(f"Added {added_csv_count} cases to cases.csv")
