# Threat Intelligence to SOC Dashboard

A production-inspired tool that bridges Threat Intelligence, SOC Operations, Detection Engineering, Adversary Analysis, and Customer Security Communication. This script fetches live threat intelligence, prioritizes indicators, generates an analyst-friendly dashboard, and produces outputs for multiple security roles.

## The Problem This Solves

Security teams face a broken workflow:
- Threat intelligence feeds produce thousands of indicators daily with no prioritization
- SOC analysts waste hours triaging low-confidence IOCs
- Detection engineers never see the intel needed to write new rules
- Customers receive confusing or alarming threat reports

This tool solves the "last mile" problem by turning raw threat intelligence into actionable outputs for every role.

## What This Project Demonstrates

| Role | Evidence in this project |
|------|--------------------------|
| Threat Intelligence | Fetches live IOC feeds from AlienVault OTX, extracts structured indicators |
| SOC Operations | Priority scoring (HIGH/MEDIUM/LOW), clear SOC actions, SIEM export formats |
| Detection Engineering | Sigma rule templates, MITRE ATT&CK mapping, watchlist generation |
| Adversary Analysis | Maps indicators to adversary TTPs using MITRE technique hints |
| Customer Communication | Generates risk-level summaries with plain English recommendations |

## How It Works

Step 1: Fetch
The script connects to AlienVault OTX API and retrieves threat pulses from the last 7 days.

Step 2: Extract and Prioritize
Indicators (IPs, domains, URLs) are extracted and scored:
- HIGH: Tags contain ransomware, C2, malware, APT, emotet
- MEDIUM: Tags contain phishing, scanner, botnet
- LOW: All other indicators

Step 3: Enrich
Each IOC receives:
- A clear SOC action (BLOCK IMMEDIATELY, MONITOR, or LOG ONLY)
- MITRE ATT&CK technique hint
- Network context (private or public IP)

Step 4: Generate Outputs
The script produces five different outputs for five different roles.

## Outputs

| Output | Format | Audience |
|--------|--------|----------|
| HTML Dashboard | Web page | SOC analysts for daily triage |
| CSV Export | Spreadsheet | SOC leads for SIEM ingestion |
| SIEM Watchlist | Text file | Engineers for manual blocking |
| Detection Notes | Console output | Detection engineers for rule writing |
| Customer Summary | Console output | Customer success team |

## Quick Start

Prerequisites:
- Python 3.7 or higher
- Internet connection for API access

Installation:

```bash
git clone https://github.com/YOUR_USERNAME/ti-soc-dashboard
cd ti-soc-dashboard
pip install -r requirements.txt