import json
import csv
from datetime import datetime
from pathlib import Path

# Load AI results
with open("ai_diagnosis_results.json", "r", encoding="utf-8") as f:
    ai_data = json.load(f)

results = ai_data.get("results", [])

# Define the human corrections for 5 cases
corrections = {
    "18": {
        "status": "Edited",
        "reviewer_reason": "AI missed that the interface is an inter-switch trunk, which is the key error since PortFast should only be enabled on edge ports.",
        "corrected_root_cause": "STP PortFast is incorrectly enabled on interface FastEthernet0/1, which is a trunk link connected to Switch1. This bypasses STP checks and creates a risk of Layer 2 loops.",
        "corrected_fix_steps": [
            "Enter interface configuration mode for FastEthernet0/1.",
            "Disable PortFast with 'no spanning-tree portfast'.",
            "Verify that spanning tree loop prevention is active on the trunk interface."
        ],
        "correction_summary": "The AI should have identified that the interface is an inter-switch trunk, making PortFast inappropriate and dangerous."
    },
    "21": {
        "status": "Edited",
        "reviewer_reason": "AI did not mention the exact cause: both static routes have the same administrative distance of 1.",
        "corrected_root_cause": "Backup static route was configured with administrative distance 1 instead of a higher value (e.g., 10), so it is not functioning as a floating backup route but is instead active concurrently (equal-cost routing).",
        "corrected_fix_steps": [
            "Remove the incorrect backup static route: 'no ip route 192.168.20.0 255.255.255.0 10.2.2.2'.",
            "Configure the floating static route with a higher AD: 'ip route 192.168.20.0 255.255.255.0 10.2.2.2 10'.",
            "Verify routing table shows only the primary route under normal conditions."
        ],
        "correction_summary": "AI failed to specify the administrative distance mismatch that caused the backup route to be treated as equal to the primary."
    },
    "25": {
        "status": "Edited",
        "reviewer_reason": "AI missed the crucial detail that standard ACLs applied inbound on egress interfaces filter based on source, which blocks all WAN ingress.",
        "corrected_root_cause": "Standard ACL 10 is applied in the wrong direction (inbound 'in' instead of outbound 'out') on the GigabitEthernet0/0/0 egress interface.",
        "corrected_fix_steps": [
            "Enter interface configuration mode for GigabitEthernet0/0/0.",
            "Remove the inbound ACL application: 'no ip access-group 10 in'.",
            "Apply the access list in the correct direction or location if traffic filtering is required."
        ],
        "correction_summary": "The AI did not state that the standard ACL was applied inbound on the egress interface."
    },
    "29": {
        "status": "Edited",
        "reviewer_reason": "AI did not specify that the ACL matches 192.168.1.0/24 while the actual LAN subnet is 192.168.2.0/24.",
        "corrected_root_cause": "NAT Access List 1 is configured to permit subnet 192.168.1.0/24, which mismatches the actual LAN subnet of 192.168.2.0/24 configured on interface GigabitEthernet0/0/1.",
        "corrected_fix_steps": [
            "Update standard access-list 1 to match the actual LAN subnet: 'access-list 1 permit 192.168.2.0 0.0.0.255'.",
            "Clear NAT translations table: 'clear ip nat translation *'.",
            "Verify NAT translations are dynamically populated when LAN devices generate traffic."
        ],
        "correction_summary": "The AI failed to identify the specific subnet mismatch between the access list and the inside interface."
    },
    "30": {
        "status": "Edited",
        "reviewer_reason": "AI did not point out that the inside local and inside global IPs were inverted in the command parameters.",
        "corrected_root_cause": "Static NAT mapping has parameters inverted (configured with public IP first, i.e., 'ip nat inside source static 203.0.113.10 192.168.1.50' instead of local IP first).",
        "corrected_fix_steps": [
            "Remove the inverted static NAT configuration: 'no ip nat inside source static 203.0.113.10 192.168.1.50'.",
            "Configure the correct static NAT command with local IP first: 'ip nat inside source static 192.168.1.50 203.0.113.10'.",
            "Verify that external users can reach the internal server via the public IP."
        ],
        "correction_summary": "The AI did not state that the public and private IP parameters were inverted."
    }
}

reviews = []

for case in results:
    case_id = str(case.get("case_id"))
    ai_rc = case.get("diagnosis", {}).get("root_cause", "")
    
    if case_id in corrections:
        corr = corrections[case_id]
        review = {
            "case_id": case_id,
            "status": corr["status"],
            "reviewed_at": datetime.now().isoformat(timespec="seconds"),
            "reviewer_reason": corr["reviewer_reason"],
            "ai_root_cause": ai_rc,
            "corrected_root_cause": corr["corrected_root_cause"],
            "corrected_fix_steps": corr["corrected_fix_steps"],
            "correction_summary": corr["correction_summary"]
        }
    else:
        review = {
            "case_id": case_id,
            "status": "Accepted",
            "reviewed_at": datetime.now().isoformat(timespec="seconds"),
            "reviewer_reason": "AI diagnosis is accurate and aligns with the expected lab fault.",
            "ai_root_cause": ai_rc,
            "corrected_root_cause": "",
            "corrected_fix_steps": [],
            "correction_summary": ""
        }
    reviews.append(review)

# Save JSON log
log_data = {
    "tool": "NetSage AI - Human Review Log",
    "reviewer": "Sujal",
    "reviews": reviews
}

with open("human_review_log.json", "w", encoding="utf-8") as f:
    json.dump(log_data, f, indent=2, ensure_ascii=False)

print("Saved human_review_log.json")

# Save CSV log
with open("human_review_log.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "case_id",
        "status",
        "reviewed_at",
        "reviewer_reason",
        "ai_root_cause",
        "corrected_root_cause",
        "corrected_fix_steps",
        "correction_summary"
    ])
    for r in reviews:
        writer.writerow([
            r["case_id"],
            r["status"],
            r["reviewed_at"],
            r["reviewer_reason"],
            r["ai_root_cause"],
            r["corrected_root_cause"],
            ", ".join(r["corrected_fix_steps"]) if r["corrected_fix_steps"] else "",
            r["correction_summary"]
        ])

print("Saved human_review_log.csv")
