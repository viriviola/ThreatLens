#!/usr/bin/env python3
"""
Threat Intelligence Dashboard - Live Data from AlienVault OTX
Requires free OTX API key
"""

import requests
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# ============================================
# CONFIGURATION - ADD YOUR API KEY HERE
# ============================================

# Get your free API key from: https://otx.alienvault.com/api
OTX_API_KEY = "7a332f61dc9ffd84e8d6969757a34543431fcce2f69280fa18732a0083c01517"  # <--- PASTE YOUR API KEY HERE

# Or set as environment variable (more secure):
# OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# Priority tags
HIGH_PRIORITY_TAGS = ["ransomware", "c2", "trojan", "malware", "apt", "emotet", "trickbot", "infostealer", "cobaltstrike"]
MEDIUM_PRIORITY_TAGS = ["phishing", "scanner", "botnet", "crypto", "miner", "spam"]

# ============================================
# FETCH LIVE DATA WITH API KEY
# ============================================

def fetch_live_iocs():
    """Fetch live IOCs from AlienVault OTX using API key"""
    print("[*] Fetching live threat intelligence from AlienVault OTX...")
    
    if not OTX_API_KEY or OTX_API_KEY == "YOUR_API_KEY_HERE":
        print("[!] WARNING: No valid OTX API key found!")
        print("[!] Get a free key from: https://otx.alienvault.com/api")
        print("[!] Then add it to the OTX_API_KEY variable in this script")
        print("[!] Using sample data instead...")
        return get_sample_iocs()
    
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }
    
    try:
        response = requests.get(OTX_URL, headers=headers, timeout=30)
        print(f"[*] HTTP Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            pulses = data.get("results", [])
            print(f"[+] Success! Retrieved {len(pulses)} pulses")
        else:
            print(f"[-] API Error: {response.status_code}")
            print(f"[-] Response: {response.text[:200]}")
            return get_sample_iocs()
        
    except Exception as e:
        print(f"[-] Failed to fetch: {e}")
        print("[!] Using sample data instead...")
        return get_sample_iocs()
    
    iocs = []
    
    for pulse in pulses:
        pulse_name = pulse.get("name", "Unknown")
        pulse_tags = pulse.get("tags", [])
        
        for indicator in pulse.get("indicators", []):
            ioc_type = indicator.get("type", "").upper()
            ioc_value = indicator.get("indicator", "")
            
            # Only take IPv4, DOMAIN, URL
            if ioc_type not in ["IPv4", "DOMAIN", "URL"]:
                continue
            
            # Calculate priority based on tags
            tags_lower = [t.lower() for t in pulse_tags]
            if any(tag in tags_lower for tag in HIGH_PRIORITY_TAGS):
                priority = "HIGH"
                confidence_score = 75 + (len([t for t in tags_lower if t in HIGH_PRIORITY_TAGS]) * 5)
                confidence_score = min(95, confidence_score)
            elif any(tag in tags_lower for tag in MEDIUM_PRIORITY_TAGS):
                priority = "MEDIUM"
                confidence_score = 50
            else:
                priority = "LOW"
                confidence_score = 30
            
            # Cap confidence score
            confidence_score = max(0, min(100, confidence_score))
            confidence_level = "HIGH" if confidence_score >= 70 else "MEDIUM" if confidence_score >= 40 else "LOW"
            
            # MITRE hint based on tags
            tag_string = str(pulse_tags).lower()
            if "c2" in tag_string or "cobalt" in tag_string:
                mitre_hint = "T1071 - C2 Communication"
            elif "ransomware" in tag_string:
                mitre_hint = "T1486 - Ransomware"
            elif "phishing" in tag_string:
                mitre_hint = "T1566 - Phishing"
            elif "trojan" in tag_string:
                mitre_hint = "T1204 - User Execution"
            else:
                mitre_hint = "Review TTPs"
            
            ioc = {
                "type": ioc_type,
                "value": ioc_value,
                "pulse_name": pulse_name,
                "tags": ", ".join(pulse_tags[:4]) if pulse_tags else "No tags",
                "priority": priority,
                "confidence_score": confidence_score,
                "confidence_level": confidence_level,
                "mitre_hint": mitre_hint,
                "soc_action": "BLOCK IMMEDIATELY" if priority == "HIGH" else "MONITOR" if priority == "MEDIUM" else "LOG ONLY"
            }
            iocs.append(ioc)
    
    print(f"[+] Extracted {len(iocs)} live IOCs")
    
    # Limit to 100 IOCs for performance
    if len(iocs) > 100:
        iocs = iocs[:100]
        print(f"[+] Limited to first 100 IOCs for display")
    
    if len(iocs) == 0:
        print("[!] No IOCs extracted. Using sample data.")
        return get_sample_iocs()
    
    return iocs

def get_sample_iocs():
    """Fallback sample data if API fails"""
    print("[*] Using sample demonstration data")
    return [
        {"type": "IPv4", "value": "185.130.5.253", "pulse_name": "Emotet C2 Infrastructure", "tags": "malware, trojan, emotet, c2", "priority": "HIGH", "confidence_score": 85, "confidence_level": "HIGH", "mitre_hint": "T1071 - C2 Communication", "soc_action": "BLOCK IMMEDIATELY"},
        {"type": "DOMAIN", "value": "evil-phishing-domain.com", "pulse_name": "Q3 Phishing Campaign", "tags": "phishing, credential, theft", "priority": "MEDIUM", "confidence_score": 55, "confidence_level": "MEDIUM", "mitre_hint": "T1566 - Phishing", "soc_action": "MONITOR"},
        {"type": "IPv4", "value": "45.142.120.5", "pulse_name": "Cobalt Strike Beacon", "tags": "c2, cobaltstrike, malware", "priority": "HIGH", "confidence_score": 92, "confidence_level": "HIGH", "mitre_hint": "T1071 - C2 Communication", "soc_action": "BLOCK IMMEDIATELY"},
        {"type": "URL", "value": "hxxp://malware-drop.com/payload.exe", "pulse_name": "Malware Distribution", "tags": "trojan, downloader", "priority": "HIGH", "confidence_score": 78, "confidence_level": "HIGH", "mitre_hint": "T1204 - User Execution", "soc_action": "BLOCK IMMEDIATELY"},
        {"type": "DOMAIN", "value": "suspicious-scanner.net", "pulse_name": "Reconnaissance Activity", "tags": "scanner, recon", "priority": "LOW", "confidence_score": 25, "confidence_level": "LOW", "mitre_hint": "T1040 - Network Sniffing", "soc_action": "LOG ONLY"},
    ]

# ============================================
# GENERATE HTML TABLE ROWS
# ============================================

def generate_table_rows(iocs):
    """Generate HTML table rows as a single string"""
    rows_html = ""
    
    for ioc in iocs:
        # Priority badge class
        badge_class = f"badge-{ioc['priority'].lower()}"
        
        # Confidence bar color and class
        if ioc["confidence_score"] >= 70:
            bar_color = "#28a745"
            score_class = "confidence-high"
        elif ioc["confidence_score"] >= 40:
            bar_color = "#fd7e14"
            score_class = "confidence-medium"
        else:
            bar_color = "#dc3545"
            score_class = "confidence-low"
        
        # SOC Action HTML
        if ioc["priority"] == "HIGH":
            soc_action_html = '<span style="color: #dc3545; font-weight: bold;">BLOCK IMMEDIATELY</span>'
        elif ioc["priority"] == "MEDIUM":
            soc_action_html = '<span style="color: #fd7e14; font-weight: bold;">MONITOR</span>'
        else:
            soc_action_html = '<span style="color: #28a745; font-weight: bold;">LOG ONLY</span>'
        
        # Build the row
        row = f'''
            <tr data-priority="{ioc['priority']}" data-confidence="{ioc['confidence_level']}">
                <td><span class="{badge_class}">{ioc['priority']}</span></td>
                <td><span class="type-badge">{ioc['type']}</span></td>
                <td class="ioc-value">{ioc['value']}</td>
                <td class="tags">{ioc['tags'][:60]}</td>
                <td>{soc_action_html}</td>
                <td>
                    <div style="display: inline-flex; align-items: center; gap: 6px;">
                        <div class="confidence-bar">
                            <div class="confidence-bar-fill" style="width: {ioc['confidence_score']}%; background: {bar_color};"></div>
                        </div>
                        <span class="confidence-score {score_class}">{ioc['confidence_score']}%</span>
                    </div>
                </td>
                <td class="source">{ioc['pulse_name'][:35]}</td>
                <td class="mitre">{ioc['mitre_hint']}</td>
            </tr>
        '''
        rows_html += row
    
    return rows_html

# ============================================
# GENERATE DASHBOARD
# ============================================

def generate_dashboard():
    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE DASHBOARD")
    print("=" * 60)
    
    # Fetch live data
    iocs = fetch_live_iocs()
    
    # Calculate statistics
    stats = {
        "total_iocs": len(iocs),
        "high_priority_count": len([i for i in iocs if i["priority"] == "HIGH"]),
        "medium_priority_count": len([i for i in iocs if i["priority"] == "MEDIUM"]),
        "low_priority_count": len([i for i in iocs if i["priority"] == "LOW"]),
        "high_confidence_count": len([i for i in iocs if i["confidence_level"] == "HIGH"]),
        "avg_confidence": int(sum(i["confidence_score"] for i in iocs) / len(iocs)) if iocs else 0,
        "ip_count": len([i for i in iocs if i["type"] == "IPv4"]),
        "domain_count": len([i for i in iocs if i["type"] in ["DOMAIN", "URL"]]),
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "data_source": "LIVE AlienVault OTX" if OTX_API_KEY and OTX_API_KEY != "YOUR_API_KEY_HERE" else "Sample Data"
    }
    
    # Generate table rows HTML
    table_rows = generate_table_rows(iocs)
    
    # Load and render template
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('dashboard_template.html')
    html_output = template.render(table_rows=table_rows, **stats)
    
    # Save the dashboard
    os.makedirs("output", exist_ok=True)
    with open("output/dashboard.html", "w", encoding="utf-8") as f:
        f.write(html_output)
    
    print("\n" + "=" * 50)
    print(f"SUCCESS! Dashboard generated")
    print(f"Output: output/dashboard.html")
    print(f"Total IOCs: {len(iocs)}")
    print(f"  - HIGH priority: {stats['high_priority_count']}")
    print(f"  - MEDIUM priority: {stats['medium_priority_count']}")
    print(f"  - LOW priority: {stats['low_priority_count']}")
    print(f"Data source: {stats['data_source']}")
    print("=" * 50)
    
    return "output/dashboard.html"

# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    generate_dashboard()
    print("\nOpen 'output/dashboard.html' in your browser to view the dashboard.")