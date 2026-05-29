#!/usr/bin/env python3
"""
Threat Intelligence Feed Parser + SOC Dashboard
Fetches IOCs from AlienVault OTX, enriches, and generates HTML dashboard
"""

import requests
import json
import pandas as pd
from datetime import datetime, timedelta
from jinja2 import Environment, FileSystemLoader
import ipaddress
import os

# ============================================
# CONFIGURATION
# ============================================

# Free OTX feed - no API key needed for pulses in last 7 days
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
# You can add an API key later for higher limits: headers = {"X-OTX-API-KEY": "your_key"}

# Threat categories we care about (for SOC prioritization)
HIGH_PRIORITY_TAGS = ["ransomware", "c2", "trojan", "malware", "apt", "emotet", "trickbot", "infostealer"]
MEDIUM_PRIORITY_TAGS = ["phishing", "scanner", "botnet", "crypto", "miner"]

# ============================================
# FETCH INTELLIGENCE
# ============================================

def fetch_threat_intel():
    """Fetch recent pulses from OTX"""
    print("[*] Fetching threat intelligence from AlienVault OTX...")
    
    try:
        response = requests.get(OTX_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        pulses = data.get("results", [])
        print(f"[+] Retrieved {len(pulses)} pulses")
        return pulses
    
    except Exception as e:
        print(f"[-] Error fetching intel: {e}")
        return []

def extract_iocs_from_pulses(pulses):
    """Extract IPs, domains, and URLs from pulses"""
    iocs = []
    
    for pulse in pulses:
        pulse_name = pulse.get("name", "Unknown")
        pulse_tags = pulse.get("tags", [])
        pulse_created = pulse.get("created", "")
        pulse_description = pulse.get("description", "")[:200]  # Truncate
        
        # Extract indicators
        indicators = pulse.get("indicators", [])
        
        for indicator in indicators:
            indicator_type = indicator.get("type", "").upper()
            indicator_value = indicator.get("indicator", "")
            
            if indicator_type in ["IPv4", "DOMAIN", "URL", "HOSTNAME"]:
                # Calculate priority
                priority = calculate_priority(indicator_type, pulse_tags)
                
                iocs.append({
                    "type": indicator_type,
                    "value": indicator_value,
                    "pulse_name": pulse_name,
                    "tags": ", ".join(pulse_tags[:5]),  # First 5 tags only
                    "priority": priority,
                    "created": pulse_created[:10] if pulse_created else "Unknown",
                    "description": pulse_description
                })
    
    print(f"[+] Extracted {len(iocs)} IOCs")
    return iocs

def calculate_priority(indicator_type, tags):
    """Prioritize based on threat tags"""
    tags_lower = [t.lower() for t in tags]
    
    for high_tag in HIGH_PRIORITY_TAGS:
        if high_tag in tags_lower:
            return "HIGH"
    
    for medium_tag in MEDIUM_PRIORITY_TAGS:
        if medium_tag in tags_lower:
            return "MEDIUM"
    
    return "LOW"

# ============================================
# ENRICHMENT (Basic risk scoring)
# ============================================

def enrich_iocs(iocs):
    """Add enrichment data to IOCs"""
    print("[*] Enriching IOCs with risk data...")
    
    for ioc in iocs:
        # Check if IP is private/routable
        if ioc["type"] == "IPv4":
            try:
                ip_obj = ipaddress.ip_address(ioc["value"])
                ioc["is_private"] = ip_obj.is_private
                ioc["is_global"] = not ip_obj.is_private
            except:
                ioc["is_private"] = False
                ioc["is_global"] = True
        else:
            ioc["is_private"] = False
            ioc["is_global"] = True
        
        # Add recommended SOC action
        if ioc["priority"] == "HIGH":
            ioc["soc_action"] = "🚨 BLOCK IMMEDIATELY - Create alert rule"
        elif ioc["priority"] == "MEDIUM":
            ioc["soc_action"] = "⚠️ MONITOR - Add to watchlist for 7 days"
        else:
            ioc["soc_action"] = "ℹ️ LOG ONLY - Low confidence"
        
        # Add MITRE ATT&CK hints (simplified)
        if "c2" in ioc["tags"].lower():
            ioc["mitre_hint"] = "T1071 - Application Layer Protocol"
        elif "ransomware" in ioc["tags"].lower():
            ioc["mitre_hint"] = "T1486 - Data Encrypted for Impact"
        elif "phishing" in ioc["tags"].lower():
            ioc["mitre_hint"] = "T1566 - Phishing"
        else:
            ioc["mitre_hint"] = "Review TTPs"
    
    return iocs

# ============================================
# GENERATE DASHBOARD
# ============================================

def generate_dashboard(iocs, output_path="output/dashboard.html"):
    """Generate HTML dashboard for SOC analysts using external template"""
    
    # Create output directory if it doesn't exist
    os.makedirs("output", exist_ok=True)
    
    # Prepare statistics
    df = pd.DataFrame(iocs)
    stats = {
        "total_iocs": len(iocs),
        "high_priority": len(df[df["priority"] == "HIGH"]) if len(iocs) > 0 else 0,
        "medium_priority": len(df[df["priority"] == "MEDIUM"]) if len(iocs) > 0 else 0,
        "low_priority": len(df[df["priority"] == "LOW"]) if len(iocs) > 0 else 0,
        "ip_count": len(df[df["type"] == "IPv4"]) if len(iocs) > 0 else 0,
        "domain_count": len(df[df["type"] == "DOMAIN"]) if len(iocs) > 0 else 0,
        "url_count": len(df[df["type"] == "URL"]) if len(iocs) > 0 else 0,
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    
    # Load template from file
    try:
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('dashboard_template.html')
        html_output = template.render(iocs=iocs, stats=stats)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_output)
        
        print(f"[+] Dashboard generated: {output_path}")
        return output_path
    
    except Exception as e:
        print(f"[-] Error generating dashboard: {e}")
        print("[!] Make sure dashboard_template.html exists in the current directory")
        return None

# ============================================
# EXPORT FUNCTIONS (For SOC analysts)
# ============================================

def export_to_csv(iocs, filename="output/high_priority_iocs.csv"):
    """Export HIGH priority IOCs to CSV for SIEM ingestion"""
    high_iocs = [i for i in iocs if i["priority"] == "HIGH"]
    
    if not high_iocs:
        print("[!] No HIGH priority IOCs to export")
        return None
    
    df = pd.DataFrame(high_iocs)
    df.to_csv(filename, index=False)
    print(f"[+] Exported {len(high_iocs)} HIGH priority IOCs to {filename}")
    return filename

def generate_siem_watchlist(iocs, filename="output/siem_watchlist.txt"):
    """Generate plain text watchlist for manual SIEM entry"""
    high_iocs = [i for i in iocs if i["priority"] == "HIGH"]
    
    if not high_iocs:
        print("[!] No HIGH priority IOCs for watchlist")
        return None
    
    with open(filename, 'w') as f:
        f.write("# SOC Watchlist - HIGH Priority IOCs\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# Format: TYPE|VALUE|REASON\n\n")
        
        for ioc in high_iocs:
            f.write(f"{ioc['type']}|{ioc['value']}|{ioc['tags']}\n")
    
    print(f"[+] SIEM watchlist generated: {filename}")
    return filename

# ============================================
# DETECTION ENGINEERING NOTES
# ============================================

def print_detection_notes(iocs):
    """Print detection engineering recommendations"""
    high_priority = [i for i in iocs if i["priority"] == "HIGH"]
    
    if not high_priority:
        print("\n[!] No HIGH priority threats detected.")
        return
    
    print("\n" + "=" * 70)
    print("📢 DETECTION ENGINEERING NOTES")
    print("=" * 70)
    
    print(f"\n🔴 {len(high_priority)} HIGH priority IOCs detected")
    print("\nRecommended actions for Detection Engineering team:\n")
    
    # Group by type
    ips = [i for i in high_priority if i["type"] == "IPv4"]
    domains = [i for i in high_priority if i["type"] == "DOMAIN"]
    
    if ips:
        print(f"📡 Network Detection ({len(ips)} IPs):")
        print("   - Sigma rule template:")
        print("     ```yaml")
        print("     title: C2 Communication Detected")
        print("     status: experimental")
        print("     logsource:")
        print("         category: network_connection")
        print("     detection:")
        print("         selection:")
        print("             destination_ip:")
        for ip in ips[:3]:  # Show first 3 as example
            print(f"                 - \"{ip['value']}\"")
        print("         condition: selection")
        print("     ```\n")
    
    if domains:
        print(f"🌐 DNS Detection ({len(domains)} domains):")
        print("   - Add to DNS sinkhole")
        print("   - Monitor for DNS queries to these domains\n")
    
    print("MITRE ATT&CK Techniques to review:")
    techniques = set([i.get("mitre_hint", "") for i in high_priority])
    for technique in techniques:
        if technique:
            print(f"   - {technique}")
    
    print("\n" + "=" * 70)

# ============================================
# CUSTOMER COMMUNICATION SUMMARY
# ============================================

def print_customer_summary(iocs):
    """Generate customer-friendly summary (for comms role)"""
    high_count = len([i for i in iocs if i["priority"] == "HIGH"])
    medium_count = len([i for i in iocs if i["priority"] == "MEDIUM"])
    
    print("\n" + "=" * 70)
    print("📧 CUSTOMER COMMUNICATION SUMMARY")
    print("=" * 70)
    
    risk_level = "HIGH" if high_count > 10 else "MEDIUM" if high_count > 0 else "LOW"
    
    print(f"\n**Risk Level: {risk_level}**")
    print(f"\nIn the last 24 hours, threat intelligence identified:")
    print(f"  • {high_count} high-confidence indicators of compromise")
    print(f"  • {medium_count} medium-confidence indicators")
    
    if high_count > 0:
        print("\n**Recommended Customer Actions:**")
        print("  1. Review firewall logs for outbound connections to the IPs listed")
        print("  2. Ensure EDR signatures are up to date")
        print("  3. Schedule a threat hunting exercise for next 48 hours")
    else:
        print("\n**Customer Guidance:**")
        print("  No immediate action required. Continue standard monitoring.")
    
    print("\n*This summary is generated from automated threat intelligence. For urgent matters, contact SOC directly.*")
    print("=" * 70)

# ============================================
# MAIN EXECUTION
# ============================================

def main():
    print("=" * 70)
    print("🛡️  Threat Intelligence to SOC Dashboard")
    print("   (TI → SOC → Detection Engineering → Customer Comms)")
    print("=" * 70)
    
    # Step 1: Fetch intelligence
    pulses = fetch_threat_intel()
    
    if not pulses:
        print("[-] No intelligence retrieved. Using sample data for demonstration...")
        # Sample data for testing
        iocs = [
            {"type": "IPv4", "value": "185.130.5.253", "pulse_name": "Emotet C2", "tags": "malware,trojan", "priority": "HIGH", "created": "2024-01-15", "description": "Emotet C2 server"},
            {"type": "DOMAIN", "value": "evil-domain.com", "pulse_name": "Phishing Campaign", "tags": "phishing", "priority": "MEDIUM", "created": "2024-01-14", "description": "Fake login page"},
            {"type": "IPv4", "value": "45.142.120.5", "pulse_name": "Cobalt Strike", "tags": "c2,malware", "priority": "HIGH", "created": "2024-01-16", "description": "Cobalt Strike beacon"},
            {"type": "URL", "value": "hxxp://malware-site[.]com/payload.exe", "pulse_name": "Malware Distribution", "tags": "trojan,downloader", "priority": "HIGH", "created": "2024-01-16", "description": "Malicious payload"},
        ]
    else:
        # Step 2: Extract IOCs
        iocs = extract_iocs_from_pulses(pulses)
    
    # Step 3: Enrich
    iocs = enrich_iocs(iocs)
    
    # Step 4: Generate dashboard
    dashboard_path = generate_dashboard(iocs)
    
    # Step 5: Export formats for SOC
    export_to_csv(iocs)
    generate_siem_watchlist(iocs)
    
    # Step 6: Print detection notes (for Detection Engineering role)
    print_detection_notes(iocs)
    
    # Step 7: Print customer summary (for Customer Comms role)
    print_customer_summary(iocs)
    
    # Final output
    print("\n" + "=" * 70)
    print("✅ WORKFLOW COMPLETE")
    print("=" * 70)
    if dashboard_path:
        print(f"📁 Dashboard: file://{os.path.abspath(dashboard_path)}")
    print(f"📁 CSV export: output/high_priority_iocs.csv")
    print(f"📁 SIEM watchlist: output/siem_watchlist.txt")
    print("\n💡 Open the HTML dashboard in your browser to see the SOC view")
    print("=" * 70)
    
    return iocs

if __name__ == "__main__":
    iocs = main()