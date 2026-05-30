# test_api.py
import requests

print("Testing AlienVault OTX API...")
try:
    response = requests.get("https://otx.alienvault.com/api/v1/pulses/subscribed", timeout=30)
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        pulses = data.get("results", [])
        print(f"Success! Found {len(pulses)} pulses")
        
        # Show first pulse as example
        if pulses:
            print(f"\nFirst pulse name: {pulses[0].get('name', 'Unknown')}")
            indicators = pulses[0].get("indicators", [])
            print(f"Indicators in first pulse: {len(indicators)}")
    else:
        print(f"Failed with status: {response.status_code}")
        
except Exception as e:
    print(f"Error: {e}")