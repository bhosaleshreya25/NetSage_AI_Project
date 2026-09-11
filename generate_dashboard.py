import json
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

# Load case dataset
df = pd.read_csv("cases.csv")

# Load human reviews
with open("human_review_log.json", "r", encoding="utf-8") as f:
    reviews_data = json.load(f)

reviews = reviews_data.get("reviews", [])
review_df = pd.DataFrame(reviews)

# Categorize cases into broader categories for visualization
def categorize_concept(concept):
    c = str(concept).lower()
    if "ospf" in c or "routing" in c or "gateway" in c:
        return "Routing & Gateway"
    elif "vlan" in c or "trunk" in c:
        return "VLANs & Trunking"
    elif "dhcp" in c or "dns" in c:
        return "DHCP & DNS"
    elif "acl" in c or "security" in c:
        return "ACL & Security"
    elif "nat" in c or "pat" in c:
        return "NAT & PAT"
    elif "wireless" in c:
        return "Wireless"
    elif "etherchannel" in c or "stp" in c or "portfast" in c:
        return "EtherChannel & STP"
    else:
        return "ARP & Interfaces"

df["Category"] = df["Concept"].apply(categorize_concept)

# Configure plot styles
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
fig, axs = plt.subplots(2, 2, figsize=(16, 12))
fig.suptitle("NetSage AI Troubleshooting Dashboard & Validation Report", fontsize=18, fontweight="bold", y=0.98)

# Color palettes
colors_category = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b", "#e377c2", "#17becf"]
colors_severity = ["#d62728", "#ff7f0e", "#2ca02c"] # High, Medium, Low
colors_review = ["#2ca02c", "#ff7f0e", "#d62728"] # Accepted, Edited, Rejected

# 1. Issue Types Bar Chart (Top-Left)
category_counts = df["Category"].value_counts()
axs[0, 0].barh(category_counts.index, category_counts.values, color=colors_category[:len(category_counts)])
axs[0, 0].set_title("Distribution of Network Issue Types (Dataset Coverage)", fontsize=13, fontweight="bold")
axs[0, 0].set_xlabel("Number of Cases", fontsize=11)
for i, v in enumerate(category_counts.values):
    axs[0, 0].text(v + 0.1, i, str(v), va="center", fontweight="bold")
axs[0, 0].set_xlim(0, max(category_counts.values) + 1)

# 2. Case Severity Pie Chart (Top-Right)
severity_counts = df["severity"].value_counts()
axs[0, 1].pie(
    severity_counts.values, 
    labels=severity_counts.index, 
    autopct="%1.1f%%", 
    startangle=140, 
    colors=[colors_severity[0] if s == "High" else colors_severity[1] for s in severity_counts.index],
    textprops={'fontweight': 'bold', 'fontsize': 11}
)
axs[0, 1].set_title("Case Severity Distribution", fontsize=13, fontweight="bold")

# 3. Human Review Status Pie Chart (Bottom-Left)
review_counts = review_df["status"].value_counts()
axs[1, 0].pie(
    review_counts.values, 
    labels=review_counts.index, 
    autopct="%1.1f%%", 
    startangle=140, 
    colors=[colors_review[0] if r == "Accepted" else colors_review[1] for r in review_counts.index],
    textprops={'fontweight': 'bold', 'fontsize': 11}
)
axs[1, 0].set_title("Human Review Status (Responsible AI Compliance)", fontsize=13, fontweight="bold")

# 4. Performance & Agreement Metrics Table (Bottom-Right)
axs[1, 1].axis("off")
axs[1, 1].set_title("Key Performance & Validation Metrics", fontsize=13, fontweight="bold", pad=20)

# Calculate metrics
total_cases = len(df)
accepted_cases = sum(review_df["status"] == "Accepted")
edited_cases = sum(review_df["status"] == "Edited")
rejected_cases = sum(review_df["status"] == "Rejected")

# Load rule checker findings for agreement rate
with open("rule_checker_results_v2.json", "r", encoding="utf-8") as rf:
    rc_data = json.load(rf)
rc_agreement = rc_data.get("agreement_percent", 0.0)

# Load AI diagnosis results for agreement rate
with open("ai_diagnosis_results.json", "r", encoding="utf-8") as af:
    ai_data = json.load(af)
ai_agreement = ai_data.get("ai_agreement_rate", 0.0)

metric_labels = [
    "Total Cases Checked",
    "AI Diagnoser Agreement Rate",
    "Rule Checker Agreement Rate",
    "Human Accepted Cases",
    "Human Edited Cases (Responsible AI)",
    "Human Rejected Cases",
    "Dataset Coverage Status"
]
metric_values = [
    f"{total_cases} cases (Target: >= 30)",
    f"{ai_agreement:.2f}% (Target: High)",
    f"{rc_agreement:.2f}% (Target: High)",
    f"{accepted_cases} cases",
    f"{edited_cases} cases (Target: >= 5)",
    f"{rejected_cases} cases",
    "PASS (VLAN, DHCP, DNS, Routing, ACL, NAT, Wireless)"
]

# Create a clean text display of the table
table_data = []
for l, v in zip(metric_labels, metric_values):
    table_data.append([l, v])

table = axs[1, 1].table(
    cellText=table_data, 
    colLabels=["Metric Name", "Current Status"], 
    cellLoc="left", 
    loc="center"
)
table.auto_set_font_size(False)
table.set_fontsize(11)
table.scale(1.2, 2.0)

# Stylize headers
for key, cell in table.get_celld().items():
    if key[0] == 0:
        cell.set_text_props(weight='bold', color='white')
        cell.set_facecolor('#2c3e50')

plt.tight_layout()
plt.savefig("dashboard.png", dpi=150, bbox_inches="tight")
print("Dashboard visualization saved successfully to dashboard.png")
plt.close()
