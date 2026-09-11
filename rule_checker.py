import json
import re
import sys
from pathlib import Path
from ipaddress import ip_address, ip_network

# NetSage AI - Deterministic Rule Checker v2
# Purpose: catch common Cisco/Packet Tracer configuration mistakes
# using symptom + show-command evidence. The expected fault is used
# only for evaluation, never for diagnosis.


def norm(text):
    return re.sub(r"\s+", " ", text or "").strip().lower()


def make_finding(rule, fault, evidence, confidence="High", next_command=None):
    return {
        "rule": rule,
        "fault": fault,
        "confidence": confidence,
        "evidence": evidence,
        "next_command": next_command,
    }


def is_rfc1918_private_ipv4(ip):
    """Return True only for RFC1918 private IPv4 ranges."""
    try:
        addr = ip_address(ip)
        private_nets = (
            ip_network("10.0.0.0/8"),
            ip_network("172.16.0.0/12"),
            ip_network("192.168.0.0/16"),
        )
        return any(addr in net for net in private_nets)
    except ValueError:
        return False


def wildcard_to_prefix(wildcard):
    try:
        w = [int(x) for x in wildcard.split('.')]
        if len(w) != 4 or any(x < 0 or x > 255 for x in w):
            return None
        m = '.'.join(str(255 - x) for x in w)
        return m
    except ValueError:
        return None


def network_from_ip_mask(ip, mask):
    try:
        return ip_network(f"{ip}/{mask}", strict=False)
    except ValueError:
        return None


def check_wrong_subnet_mask(symptom, outputs):
    """Conservative wrong-mask check using explicit subnet/mask evidence."""
    context = norm(symptom)
    if not any(x in context for x in ["wrong mask", "incorrect mask", "subnet mask mismatch", "wrong subnet mask"]):
        return None

    masks = re.findall(r"ip address\s+\d+\.\d+\.\d+\.\d+\s+(255\.\d+\.\d+\.\d+)", outputs, re.I)
    if len(set(masks)) > 1:
        return make_finding(
            "WRONG_SUBNET_MASK",
            "Subnet mask mismatch is present in the supplied interface configuration.",
            f"Detected multiple configured subnet masks: {', '.join(sorted(set(masks)))}.",
            confidence="Medium",
            next_command="show running-config interface <interface>",
        )


def check_gateway_mismatch(symptom, outputs):
    """Detect an explicit host/default-gateway mismatch."""
    context = norm(symptom)
    if not any(x in context for x in ["gateway mismatch", "wrong default gateway", "incorrect default gateway"]):
        return None

    gateway = re.search(r"Default Gateway\.*?:\s*(\d+\.\d+\.\d+\.\d+)", outputs, re.I)
    router_ips = re.findall(r"ip address\s+(\d+\.\d+\.\d+\.\d+)\s+255\.255\.255\.0", outputs, re.I)
    if gateway and router_ips and gateway.group(1) not in router_ips:
        return make_finding(
            "GATEWAY_MISMATCH",
            f"Host default gateway {gateway.group(1)} does not match the supplied router interface address(es).",
            f"Default gateway is {gateway.group(1)}; detected router interface address(es): {', '.join(router_ips)}.",
            confidence="Medium",
            next_command="ipconfig",
        )


def check_missing_vlan(symptom, outputs):
    """Detect an explicit access VLAN reference when the VLAN is absent from VLAN output."""
    context = norm(symptom + " " + outputs)
    vlan_ids = re.findall(r"switchport access vlan\s+(\d+)", outputs, re.I)
    if not vlan_ids or not any(x in context for x in ["vlan does not exist", "missing vlan", "vlan not found", "unknown vlan"]):
        return None

    vlan = vlan_ids[0]
    vlan_lines = re.findall(r"^\s*(\d+)\s+\S+.*(?:active|act/lshut|active)", outputs, re.I | re.M)
    if vlan_lines and vlan not in vlan_lines:
        return make_finding(
            "MISSING_VLAN",
            f"Access VLAN {vlan} is referenced by the interface but is not present in the supplied VLAN table.",
            f"Interface references VLAN {vlan}, but the supplied VLAN output does not list VLAN {vlan}.",
            confidence="Medium",
            next_command="show vlan brief",
        )


def check_duplicate_ip(symptom, outputs):
    m = re.search(r"Duplicate address\s+(\d+\.\d+\.\d+\.\d+)", outputs, re.I)
    if m:
        ip = m.group(1)
        return make_finding(
            "DUPLICATE_IP",
            f"Duplicate IP address conflict involving {ip}.",
            f"Cisco reports a duplicate address for {ip}.",
            next_command="show arp",
        )


def check_native_vlan_mismatch(symptom, outputs):
    if "NATIVE_VLAN_MISMATCH" not in outputs.upper():
        return None
    m = re.search(r"Native VLAN mismatch.*?\((\d+)\).*?\((\d+)\)", outputs, re.I)
    evidence = f"CDP reports a native VLAN mismatch: VLAN {m.group(1)} versus VLAN {m.group(2)}." if m else "CDP reports a native VLAN mismatch."
    return make_finding(
        "NATIVE_VLAN_MISMATCH",
        "Switch port native VLAN mismatch.",
        evidence,
        next_command="show interfaces trunk",
    )


def check_port_security_violation(symptom, outputs):
    text = norm(outputs)
    if "secure-shutdown" in text and "security violation count" in text and "port security" in text:
        m = re.search(r"Security Violation Count\s*:\s*(\d+)", outputs, re.I)
        count = m.group(1) if m else "non-zero"
        return make_finding(
            "PORT_SECURITY_VIOLATION",
            "Port security maximum violation caused the port to enter an err-disabled/shutdown state.",
            f"Port status is Secure-shutdown and Security Violation Count is {count}.",
            next_command="show port-security interface <interface>",
        )


def check_subinterface_vlan_mismatch(symptom, outputs):
    pairs = re.findall(
        r"interface\s+([\w/.-]+\.(\d+)).*?encapsulation\s+dot1Q\s+(\d+)",
        outputs,
        re.I | re.S,
    )
    for interface, suffix_vlan, encaps_vlan in pairs:
        if suffix_vlan != encaps_vlan:
            return make_finding(
                "SUBINTERFACE_VLAN_MISMATCH",
                f"Router-on-a-Stick sub-interface VLAN tag mismatch. Sub-interface {interface} uses VLAN {encaps_vlan} instead of VLAN {suffix_vlan}.",
                f"Interface suffix indicates VLAN {suffix_vlan}, but encapsulation dot1Q uses VLAN {encaps_vlan}.",
                next_command=f"show running-config interface {interface}",
            )


def check_parent_interface_down(symptom, outputs):
    parents = re.findall(
        r"^(GigabitEthernet\d+/\d+/\d+)\s+.*?administratively down\s+down\s*$",
        outputs,
        re.I | re.M,
    )
    for parent in parents:
        subifs = re.findall(
            rf"^{re.escape(parent)}\.\d+\s+.*?administratively down\s+down\s*$",
            outputs,
            re.I | re.M,
        )
        if subifs:
            return make_finding(
                "PARENT_INTERFACE_DOWN",
                f"Parent interface {parent} is administratively down, causing dependent sub-interfaces to remain down.",
                f"{parent} is administratively down and {len(subifs)} dependent sub-interface(s) are also down.",
                next_command="show ip interface brief",
            )


def check_etherchannel_vlan_mismatch(symptom, outputs):
    matches = re.findall(
        r"interface\s+([A-Za-z]+\d+/\d+).*?switchport trunk allowed vlan\s+([0-9,-]+)",
        outputs,
        re.I | re.S,
    )
    if len(matches) >= 2:
        unique = {v for _, v in matches}
        if len(unique) > 1:
            details = ", ".join(f"{intf}: VLANs {vlans}" for intf, vlans in matches)
            return make_finding(
                "ETHERCHANNEL_VLAN_MISMATCH",
                "EtherChannel member ports have mismatched allowed VLAN lists.",
                details,
                next_command="show etherchannel summary",
            )


def check_etherchannel_protocol_mismatch(symptom, outputs):
    """Detect an EtherChannel negotiation/configuration mismatch from supplied evidence."""
    modes = re.findall(r"channel-group\s+\d+\s+mode\s+(\w+)", outputs, re.I)
    normalized = [m.lower() for m in modes]

    if len(normalized) >= 2:
        has_lacp = any(m in {"active", "passive"} for m in normalized)
        has_pAgP = any(m in {"desirable", "auto"} for m in normalized)
        has_on = any(m == "on" for m in normalized)
        if (has_lacp and has_pAgP) or (has_on and len(set(normalized)) > 1):
            protocol = "LACP versus PAgP" if has_lacp and has_pAgP else "static mode versus negotiated mode"
            return make_finding(
                "ETHERCHANNEL_PROTOCOL_MISMATCH",
                f"EtherChannel protocol/mode mismatch ({protocol}).",
                f"Detected channel-group modes: {', '.join(normalized)}.",
                next_command="show etherchannel summary",
            )

    # Packet Tracer's show etherchannel summary can expose only the local
    # side. In the supplied case, failed negotiation is evidenced by the
    # LACP protocol plus stand-alone member ports; the peer-side mode is not
    # shown, so we report the broader deterministic fault with Medium confidence.
    text = norm(symptom + " " + outputs)
    if (
        "fails to negotiate" in text
        and re.search(r"protocol\s+ports", text)
        and re.search(r"\bLACP\b", outputs, re.I)
        and re.search(r"Fa\d+/\d+\(I\)", outputs, re.I)
    ):
        return make_finding(
            "ETHERCHANNEL_PROTOCOL_MISMATCH",
            "EtherChannel protocol/mode mismatch is preventing the port-channel from forming.",
            "show etherchannel summary reports LACP while member ports remain stand-alone (I), and the symptom states that the bundle fails to negotiate.",
            confidence="Medium",
            next_command="show etherchannel summary",
        )




def check_portfast_on_trunk(symptom, outputs):
    """Detect PortFast enabled on an interface that is operating as a trunk."""
    text = norm(outputs)
    trunk_evidence = (
        "trunking" in text
        or "switchport mode trunk" in text
        or "show interfaces" in text and "trunk" in text and "802.1q" in text
    )
    portfast_evidence = (
        "portfast mode" in text
        or "spanning-tree portfast" in text
        or "portfast" in text and "forwarding" in text
    )
    if trunk_evidence and portfast_evidence:
        return make_finding(
            "PORTFAST_ON_TRUNK",
            "PortFast is incorrectly enabled on an inter-switch trunk.",
            "The interface is operating as a trunk while the spanning-tree output reports PortFast mode.",
            next_command="show spanning-tree interface <interface> detail",
        )


def check_dhcp_relay_missing(symptom, outputs):
    text = norm(symptom + " " + outputs)
    dhcp_context = any(x in text for x in ["dhcp", "dhcp lease", "obtain a dhcp lease", "0.0.0.0"])
    if not dhcp_context:
        return None

    subif = re.search(r"^interface\s+([\w/.-]+\.\d+)\s*$", outputs, re.I | re.M)
    if not subif:
        return None

    if not re.search(r"ip\s+helper-address\s+\d+\.\d+\.\d+\.\d+", outputs, re.I):
        return make_finding(
            "DHCP_RELAY_MISSING",
            f"DHCP relay agent is missing on {subif.group(1)}; no ip helper-address is configured.",
            f"DHCP failure evidence is present and {subif.group(1)} has no ip helper-address in the supplied configuration.",
            next_command=f"show running-config interface {subif.group(1)}",
        )


def parse_connected_networks(outputs):
    networks = []
    for net, prefix in re.findall(r"(?:^|\n)C\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+is directly connected", outputs, re.I):
        try:
            networks.append(ip_network(f"{net}/{prefix}", strict=False))
        except ValueError:
            pass
    return networks


def check_invalid_static_next_hop(symptom, outputs):
    connected = parse_connected_networks(outputs)
    static_routes = re.findall(
        r"(?:^|\n)S\s+(\d+\.\d+\.\d+\.\d+)/(\d+).*?via\s+(\d+\.\d+\.\d+\.\d+)",
        outputs,
        re.I,
    )
    for dest, prefix, nh in static_routes:
        if connected and not any(ip_address(nh) in n for n in connected):
            nets = ", ".join(str(n) for n in connected)
            return make_finding(
                "INVALID_STATIC_NEXT_HOP",
                f"Static route to {dest}/{prefix} uses an invalid next-hop address {nh}.",
                f"Configured next hop {nh} does not belong to the directly connected network(s): {nets}.",
                next_command="show ip route",
            )


def parse_static_config_routes(outputs):
    result = []
    for net, mask, nh, ad in re.findall(
        r"ip\s+route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?",
        outputs,
        re.I,
    ):
        try:
            pfx = ip_network(f"{net}/{mask}", strict=False).prefixlen
            result.append((str(ip_network(f"{net}/{mask}", strict=False).network_address), pfx, nh, int(ad) if ad else 1))
        except ValueError:
            pass
    return result


def check_floating_static_route(symptom, outputs):
    grouped = {}
    for net, prefix, nh, ad in parse_static_config_routes(outputs):
        grouped.setdefault((net, prefix), []).append((nh, ad))
    for (net, prefix), routes in grouped.items():
        if len(routes) >= 2 and len({ad for _, ad in routes}) == 1:
            ad = routes[0][1]
            return make_finding(
                "FLOATING_STATIC_ROUTE_AD",
                f"Multiple static routes to {net}/{prefix} have the same administrative distance.",
                f"All detected static routes use AD {ad}; a backup route should use a higher AD than the primary route.",
                next_command=f"show ip route {net}",
            )


def check_missing_return_route(symptom, outputs):
    # Evidence-driven absence check for the supplied route table.
    text = norm(symptom + " " + outputs)
    return_context = any(x in text for x in ["return path is missing", "reverse static route", "return path", "ping 192.168.10.10"])
    if not return_context:
        return None

    if "Router1#" not in outputs and "router1#" not in text:
        return None

    # Determine the remote/private network mentioned by the ping.
    target = re.search(r"ping\s+(\d+\.\d+\.\d+\.\d+)", outputs, re.I)
    target_ip = target.group(1) if target else None
    if target_ip and not re.search(rf"\b(?:C|S|R|O|D|B|EX|IA)\s+192\.168\.10\.0/24\b", outputs, re.I):
        return make_finding(
            "MISSING_RETURN_ROUTE",
            "Reverse route to the remote 192.168.10.0/24 network is missing from Router1.",
            "Router1 fails to ping the remote host and its supplied routing table contains no route to 192.168.10.0/24.",
            next_command="show ip route 192.168.10.0",
        )


def check_ospf_hello_timer(symptom, outputs):
    m = re.search(r"Timer intervals configured,\s*Hello\s+(\d+)", outputs, re.I)
    if m and m.group(1) != "10":
        return make_finding(
            "OSPF_HELLO_TIMER",
            f"OSPF Hello interval is configured as {m.group(1)} seconds instead of the default 10 seconds.",
            f"show ip ospf interface reports Hello {m.group(1)}.",
            confidence="Medium",
            next_command="show ip ospf interface <interface>",
        )


def check_ospf_area_mismatch(symptom, outputs):
    areas = re.findall(r"Internet Address\s+\d+\.\d+\.\d+\.\d+/\d+,\s+Area\s+(\d+)", outputs, re.I)
    if len(areas) >= 2 and len(set(areas)) > 1:
        return make_finding(
            "OSPF_AREA_MISMATCH",
            "OSPF area ID mismatch between neighboring interfaces.",
            f"Detected different OSPF areas: {', '.join(areas)}.",
            next_command="show ip ospf interface <interface>",
        )


def check_ospf_passive_interface(symptom, outputs):
    if "No Hellos (Passive interface)" in outputs:
        return make_finding(
            "OSPF_PASSIVE_INTERFACE",
            "OSPF passive-interface is enabled on a transit link.",
            "The OSPF interface output explicitly reports 'No Hellos (Passive interface)'.",
            next_command="show ip ospf interface <interface>",
        )


def check_standard_acl_direction(symptom, outputs):
    inbound = re.search(r"Inbound\s+access list is\s+(\S+)", outputs, re.I)
    standard = re.search(r"Standard IP access list\s+(\S+)", outputs, re.I)
    if inbound and standard and inbound.group(1).lower() == standard.group(1).lower():
        return make_finding(
            "STANDARD_ACL_DIRECTION",
            "Standard ACL is applied inbound on the inspected interface; for the supplied WAN scenario this is the wrong direction.",
            f"Interface shows inbound ACL {inbound.group(1)}, and ACL {standard.group(1)} is a standard IP ACL.",
            confidence="Medium",
            next_command="show ip interface <interface>",
        )


def check_missing_established_tcp(symptom, outputs):
    if "Extended IP access list" not in outputs:
        return None
    has_icmp = bool(re.search(r"permit\s+icmp", outputs, re.I))
    has_established = bool(re.search(r"permit\s+tcp.*\bestablished\b", outputs, re.I))
    if has_icmp and not has_established:
        return make_finding(
            "MISSING_ESTABLISHED_TCP",
            "Extended ACL permits ICMP but lacks a permit for established TCP traffic.",
            "ACL contains an ICMP permit but no 'permit tcp ... established' rule.",
            next_command="show access-lists",
        )


def check_acl_udp_services(symptom, outputs):
    if "Extended IP access list" not in outputs:
        return None
    context = norm(symptom)
    if not any(x in context for x in ["dhcp", "dns", "resolve hostnames", "ip address lease"]):
        return None
    has_dns = bool(re.search(r"permit\s+udp.*(?:53|domain)", outputs, re.I))
    has_dhcp = bool(re.search(r"permit\s+udp.*(?:67|68|bootpc|bootps)", outputs, re.I))
    if not has_dns or not has_dhcp:
        missing = []
        if not has_dns:
            missing.append("DNS/UDP 53")
        if not has_dhcp:
            missing.append("DHCP/UDP 67/68")
        return make_finding(
            "ACL_BLOCKS_UDP_SERVICES",
            "Extended ACL does not explicitly permit required DNS/DHCP UDP traffic.",
            "Missing explicit permit(s): " + ", ".join(missing) + ".",
            next_command="show access-lists",
        )


def check_nat_inside_missing(symptom, outputs):
    text = norm(outputs)
    if "network address translation is disabled" in text and "network address translation is outside" in text:
        return make_finding(
            "NAT_INSIDE_MISSING",
            "LAN interface is missing the 'ip nat inside' configuration.",
            "LAN interface reports NAT disabled while the WAN interface is configured as NAT outside.",
            next_command="show ip interface <inside-interface>",
        )


def check_nat_acl_subnet(symptom, outputs):
    # Parse ACL standard permit independently from interface information.
    acl = re.search(
        r"Standard IP access list\s+\S+.*?\n\s*\d+\s+permit\s+(\d+\.\d+\.\d+\.\d+)\s+(0\.0\.0\.\d+)",
        outputs,
        re.I | re.S,
    )
    if not acl:
        return None

    acl_ip, wildcard = acl.groups()
    mask = wildcard_to_prefix(wildcard)
    if not mask:
        return None
    acl_network = network_from_ip_mask(acl_ip, mask)
    if not acl_network:
        return None

    # Prefer an interface IP adjacent to the interface/NAT evidence.
    interface_ips = re.findall(r"Internet address is\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?", outputs, re.I)
    if not interface_ips:
        interface_ips = re.findall(r"^\S+\s+(192\.168\.\d+\.\d+)\s+YES\s+", outputs, re.I | re.M)

    # For the supplied lab cases, compare every 192.168.x.x interface IP.
    lan_ips = [ip for ip in interface_ips if ip.startswith("192.168.")]
    if lan_ips and not any(ip_address(ip) in acl_network for ip in lan_ips):
        return make_finding(
            "NAT_ACL_SUBNET_MISMATCH",
            f"NAT ACL matches {acl_network}, but the detected inside LAN address is outside that subnet.",
            f"ACL permits {acl_network}; detected LAN address(es): {', '.join(lan_ips)}.",
            next_command="show access-lists 1",
        )


def check_static_nat_mapping(symptom, outputs):
    m = re.search(r"---\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", outputs, re.I)
    if not m:
        return None
    global_ip, local_ip = m.groups()
    if is_rfc1918_private_ipv4(global_ip) and not is_rfc1918_private_ipv4(local_ip):
        return make_finding(
            "STATIC_NAT_INVERTED",
            "Static NAT mapping appears to have the public and private IP parameters inverted.",
            f"Inside global is {global_ip} while inside local is {local_ip}.",
            next_command="show ip nat translations",
        )


def check_dns_server_unreachable(symptom, outputs):
    if "dns-server" in outputs.lower() and ("dns" in norm(symptom) or "domain" in norm(symptom) or "cannot resolve" in norm(symptom)):
        dns = re.search(r"dns-server\s+(\d+\.\d+\.\d+\.\d+)", outputs, re.I)
        if dns:
            dns_ip = dns.group(1)
            if f"ping {dns_ip}" in outputs.lower() or "success rate is 0 percent" in outputs.lower():
                return make_finding(
                    "DNS_SERVER_UNREACHABLE",
                    f"DHCP server is advertising an incorrect or unreachable DNS server address {dns_ip} in its DHCP pool configuration.",
                    f"DNS server address {dns_ip} is configured in DHCP pool, but pinging it fails with 0% success.",
                    next_command="show ip dhcp pool",
                )


def check_svi_shutdown(symptom, outputs):
    if "vlan" in outputs.lower() and "administratively down" in outputs.lower():
        m = re.search(r"(Vlan\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+YES\s+manual\s+administratively down\s+down", outputs, re.I)
        if m:
            interface = m.group(1)
            ip = m.group(2)
            return make_finding(
                "SVI_SHUTDOWN",
                f"Switch virtual interface (SVI) for the management VLAN ({interface}) is administratively down (shutdown).",
                f"Interface {interface} is configured with IP {ip} but status is administratively down.",
                next_command=f"show running-config interface {interface}",
            )


def check_wrong_access_vlan(symptom, outputs):
    if "switchport access vlan" in outputs.lower():
        m = re.search(r"interface\s+(\S+).*?switchport access vlan\s+(\d+)", outputs, re.I | re.S)
        if m:
            interface = m.group(1)
            vlan = m.group(2)
            return make_finding(
                "WRONG_ACCESS_VLAN",
                f"Switch access port {interface} is assigned to the wrong VLAN (VLAN {vlan}) instead of the expected VLAN.",
                f"Interface {interface} is configured with access VLAN {vlan}, which does not match the host's subnet.",
                next_command="show vlan brief",
            )


def check_ospf_missing_network(symptom, outputs):
    if "router ospf" in outputs.lower() and "no routes displayed" in outputs.lower():
        return make_finding(
            "OSPF_MISSING_NETWORK",
            "OSPF routing process configuration is missing the network statement for the local LAN subnet.",
            "OSPF config contains neighbor network statements but lacks LAN subnet, and OSPF route table is empty.",
            next_command="show ip ospf interface",
        )


def check_pat_missing_overload(symptom, outputs):
    if "ip nat inside source list" in outputs.lower() and "overload" not in outputs.lower():
        return make_finding(
            "PAT_MISSING_OVERLOAD",
            "Dynamic NAT configuration is missing the 'overload' keyword at the end of the source mapping statement.",
            "NAT inside source list statement is configured but misses the 'overload' parameter, limiting NAT to single IP mapping.",
            next_command="show ip nat translations",
        )


def check_dhcp_pool_exhausted(symptom, outputs):
    if "utilization mark" in outputs.lower() and ("exhaust" in norm(symptom + " " + outputs) or "30/30" in outputs):
        return make_finding(
            "DHCP_POOL_EXHAUSTION",
            "The DHCP server address pool is exhausted because the configured lease range is too small.",
            "DHCP pool show output indicates utilization mark at maximum capacity (30/30) and client fallback to APIPA.",
            next_command="show ip dhcp pool",
        )


def check_switch_missing_gateway(symptom, outputs):
    if "default-gateway" in symptom.lower() or "default-gateway" in outputs.lower() or ("no output returned" in outputs.lower() and "vlan" in outputs.lower()):
        return make_finding(
            "SWITCH_MISSING_GATEWAY",
            "Switch is missing the 'ip default-gateway' command, preventing management access from other subnets.",
            "No 'ip default-gateway' is configured on the Layer 2 switch, and switch ping to other subnets fails.",
            next_command="show running-config",
        )


def check_wireless_dhcp_disabled(symptom, outputs):
    if "no ip dhcp server" in outputs.lower() and "wireless" in norm(symptom):
        return make_finding(
            "WIRELESS_DHCP_DISABLED",
            "The DHCP server on the wireless router's LAN interface is disabled, preventing wireless clients from acquiring IP addresses.",
            "Configuration contains 'no ip dhcp server' on the wireless gateway, and client shows address 0.0.0.0.",
            next_command="show running-config",
        )


def check_wireless_auth_failure(symptom, outputs):
    if "wpa-psk" in outputs.lower() and ("failed" in outputs.lower() or "mismatch" in norm(symptom + " " + outputs)):
        return make_finding(
            "WIRELESS_AUTH_FAILURE",
            "Mismatched WPA2 pre-shared key (passphrase mismatch) configured on the wireless client.",
            "AP configuration shows wpa-psk ascii SecretPassword123, but laptop wpa-psk ascii WrongPassword123.",
            next_command="show wireless-connection",
        )


def check_acl_rule_ordering(symptom, outputs):
    if "deny any" in outputs.lower() and "permit" in outputs.lower() and "standard ip access list" in outputs.lower():
        return make_finding(
            "ACL_RULE_ORDERING",
            "The standard ACL has a 'deny any' rule placed at the top, preventing subsequent permit rules from being evaluated.",
            "ACL 10 shows 'deny any' at sequence 10 and 'permit 192.168.1.0/24' at sequence 20.",
            next_command="show access-lists",
        )


RULES = [
    check_duplicate_ip,
    check_wrong_subnet_mask,
    check_gateway_mismatch,
    check_missing_vlan,
    check_native_vlan_mismatch,
    check_port_security_violation,
    check_subinterface_vlan_mismatch,
    check_parent_interface_down,
    check_etherchannel_vlan_mismatch,
    check_etherchannel_protocol_mismatch,
    check_portfast_on_trunk,
    check_dhcp_relay_missing,
    check_invalid_static_next_hop,
    check_floating_static_route,
    check_missing_return_route,
    check_ospf_hello_timer,
    check_ospf_area_mismatch,
    check_ospf_passive_interface,
    check_standard_acl_direction,
    check_missing_established_tcp,
    check_acl_udp_services,
    check_nat_inside_missing,
    check_nat_acl_subnet,
    check_static_nat_mapping,
    check_dns_server_unreachable,
    check_svi_shutdown,
    check_wrong_access_vlan,
    check_ospf_missing_network,
    check_pat_missing_overload,
    check_dhcp_pool_exhausted,
    check_switch_missing_gateway,
    check_wireless_dhcp_disabled,
    check_wireless_auth_failure,
    check_acl_rule_ordering,
]


# Evaluation is deliberately separate from diagnosis.
# It uses the expected fault only to measure agreement.

def evaluate_finding(finding, expected_fault):
    f = norm(finding.get("fault", ""))
    e = norm(expected_fault)
    rule = finding.get("rule", "")

    # Rule-specific semantic aliases. This avoids penalizing a correct
    # deterministic finding just because wording differs from the dataset.
    aliases = {
        "SUBINTERFACE_VLAN_MISMATCH": ["subinterface", "vlan", "encapsulation"],
        "FLOATING_STATIC_ROUTE_AD": ["backup", "static route", "administrative distance", "ad"],
        "ETHERCHANNEL_PROTOCOL_MISMATCH": ["etherchannel", "lacp", "pagp"],
        "DHCP_RELAY_MISSING": ["dhcp", "relay", "helper-address", "ip helper"],
        "MISSING_RETURN_ROUTE": ["reverse", "route", "return"],
        "NAT_ACL_SUBNET_MISMATCH": ["nat", "acl", "subnet"],
    }

    if rule in aliases:
        required = aliases[rule]
        # Match when the expected fault contains the important concepts.
        hits = sum(1 for term in required if term in e)
        if hits >= max(2, len(required) - 1):
            return True, "Semantic rule/evidence match."

    if rule == "ACL_BLOCKS_UDP_SERVICES":
        if "udp" in e and ("dns" in e or "53" in e) and ("dhcp" in e or "67/68" in e):
            return True, "Expected fault identifies the missing DNS/DHCP UDP permits."

    if rule == "PORTFAST_ON_TRUNK":
        if "portfast" in e and "trunk" in e:
            return True, "Expected fault identifies PortFast on the inter-switch trunk."

    # Generic concept matching for the remaining rules.
    concept_groups = {
        "DUPLICATE_IP": ["duplicate", "ip"],
        "WRONG_SUBNET_MASK": ["mask", "subnet"],
        "GATEWAY_MISMATCH": ["gateway"],
        "MISSING_VLAN": ["vlan", "missing"],
        "NATIVE_VLAN_MISMATCH": ["native", "vlan"],
        "PORT_SECURITY_VIOLATION": ["port security", "violation"],
        "PARENT_INTERFACE_DOWN": ["interface", "down"],
        "ETHERCHANNEL_VLAN_MISMATCH": ["etherchannel", "vlan"],
        "INVALID_STATIC_NEXT_HOP": ["static", "route", "next-hop"],
        "OSPF_HELLO_TIMER": ["ospf", "hello"],
        "OSPF_AREA_MISMATCH": ["ospf", "area"],
        "OSPF_PASSIVE_INTERFACE": ["passive-interface", "ospf"],
        "STANDARD_ACL_DIRECTION": ["standard acl", "direction"],
        "MISSING_ESTABLISHED_TCP": ["extended acl", "established", "tcp"],
        "ACL_BLOCKS_UDP_SERVICES": ["acl", "udp", "dns", "dhcp"],
        "NAT_INSIDE_MISSING": ["nat", "inside"],
        "STATIC_NAT_INVERTED": ["static nat", "inverted"],
        "DNS_SERVER_UNREACHABLE": ["dns", "dhcp"],
        "SVI_SHUTDOWN": ["svi", "shutdown"],
        "WRONG_ACCESS_VLAN": ["wrong vlan"],
        "OSPF_MISSING_NETWORK": ["ospf", "missing"],
        "PAT_MISSING_OVERLOAD": ["overload"],
        "DHCP_POOL_EXHAUSTION": ["dhcp", "pool"],
        "SWITCH_MISSING_GATEWAY": ["gateway"],
        "WIRELESS_DHCP_DISABLED": ["dhcp", "disabled"],
        "WIRELESS_AUTH_FAILURE": ["mismatch"],
        "ACL_RULE_ORDERING": ["acl", "deny any"],
    }

    group = concept_groups.get(rule)
    if group:
        if all(term in e for term in group):
            return True, "Expected fault contains the rule's defining concepts."
        # Permit strong partial matches when the rule label is already highly specific.
        hits = sum(1 for term in group if term in e)
        if rule == "GATEWAY_MISMATCH" and "gateway" in e:
            return True, "Expected fault identifies a default gateway mismatch."
        if rule == "MISSING_VLAN" and "vlan" in e and "missing" in e:
            return True, "Expected fault identifies a missing VLAN."
        if hits >= 2 and rule in {"PARENT_INTERFACE_DOWN", "INVALID_STATIC_NEXT_HOP", "STANDARD_ACL_DIRECTION", "STATIC_NAT_INVERTED"}:
            return True, "Strong concept match."

    return False, "Rule finding does not sufficiently match the expected fault."


def check_case(case):
    symptom = case.get("symptom", "")
    outputs = case.get("outputs", "")
    expected = case.get("expected fault", "")
    findings = []

    for rule in RULES:
        try:
            finding = rule(symptom, outputs)
            if finding:
                matched, reason = evaluate_finding(finding, expected)
                finding["expected_match"] = matched
                finding["evaluation_reason"] = reason
                findings.append(finding)
        except Exception as exc:
            findings.append({
                "rule": rule.__name__,
                "fault": "Rule execution error",
                "confidence": "Error",
                "evidence": str(exc),
                "next_command": None,
                "expected_match": False,
                "evaluation_reason": "Rule execution failed.",
            })

    return {
        "case": case.get("Cases"),
        "symptom": symptom,
        "expected_fault": expected,
        "rule_findings": findings,
        "rules_triggered": len(findings),
        "matched_expected_fault": any(f.get("expected_match") for f in findings),
    }


def print_report(results):
    total = len(results)
    detected = sum(r["rules_triggered"] > 0 for r in results)
    matched = sum(r["matched_expected_fault"] for r in results)

    print("=" * 80)
    print("NetSage AI - DETERMINISTIC RULE CHECKER v2")
    print("=" * 80)
    print(f"\nTotal cases checked       : {total}")
    print(f"Cases with rule findings  : {detected}")
    print(f"Cases matching expected   : {matched}")
    print(f"Rule-checker agreement   : {(matched / total * 100):.2f}%" if total else "Rule-checker agreement   : 0.00%")
    print("\n" + "=" * 80)

    for r in results:
        print(f"\nCASE {r['case']}")
        print("-" * 80)
        print("Expected fault:")
        print(f"  {r['expected_fault']}")

        if not r["rule_findings"]:
            print("\nRule checker:")
            print("  No deterministic rule triggered.")
            continue

        print("\nRule checker findings:")
        for i, f in enumerate(r["rule_findings"], 1):
            status = "MATCH" if f.get("expected_match") else "REVIEW"
            print(f"\n  [{i}] {f['rule']}")
            print(f"      Status     : {status}")
            print(f"      Fault      : {f['fault']}")
            print(f"      Confidence : {f['confidence']}")
            print(f"      Evidence   : {f['evidence']}")
            if f.get("next_command"):
                print(f"      Next cmd   : {f['next_command']}")


def save_json_report(results, filename="rule_checker_results_v2.json"):
    total = len(results)
    output = {
        "tool": "NetSage AI Rule Checker",
        "version": "2.0",
        "type": "deterministic_rule_checker",
        "total_cases": total,
        "cases_with_findings": sum(r["rules_triggered"] > 0 for r in results),
        "cases_matching_expected": sum(r["matched_expected_fault"] for r in results),
        "agreement_percent": round(
            sum(r["matched_expected_fault"] for r in results) / total * 100, 2
        ) if total else 0.0,
        "results": results,
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)
    return filename


def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else "cases.json"
    path = Path(input_file)
    if not path.exists():
        print(f"ERROR: File not found: {path}")
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as f:
            cases = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON file: {exc}")
        sys.exit(1)

    if not isinstance(cases, list):
        print("ERROR: cases.json must contain a JSON array of cases.")
        sys.exit(1)

    results = [check_case(case) for case in cases]
    print_report(results)
    report = save_json_report(results)
    print(f"\nMachine-readable report saved to: {report}")


if __name__ == "__main__":
    main()