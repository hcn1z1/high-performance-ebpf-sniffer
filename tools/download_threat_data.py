import requests
import csv
import io
import os
import zipfile
import json

OUTPUT_FILE = "tools/data/combined_ja4_db.csv"

def download_ja4plus():
    print("Downloading JA4+ Official Mapping...")
    url = "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"
    try:
        r = requests.get(url)
        r.raise_for_status()

        # Parse and standardize
        # Source Format: Application,Library,Device,OS,ja4,ja4s,ja4h,ja4x,ja4t,ja4tscan,Notes
        # Target Format: ja4,description,source,risk_level

        rows = []
        reader = csv.DictReader(io.StringIO(r.text))
        for row in reader:
            ja4 = row.get('ja4', '').strip()
            if not ja4:
                continue

            desc_parts = [row.get('Application'), row.get('Library'), row.get('OS')]
            desc = " ".join([p for p in desc_parts if p])
            if row.get('Notes'):
                desc += f" ({row['Notes']})"

            rows.append({
                'ja4': ja4,
                'description': desc if desc else "Unknown Application",
                'source': 'FoxIO-JA4DB',
                'risk_level': 'info' # Default to info for this DB
            })
        print(f"  -> Found {len(rows)} signatures")
        return rows
    except Exception as e:
        print(f"  -> Error: {e}")
        return []

def download_ja4db_official():
    print("Downloading JA4DB Official Database...")
    url = "https://ja4db.com/api/download/"
    try:
        r = requests.get(url, stream=True)
        r.raise_for_status()

        # Parse JSON
        # Structure: List of objects with fields: application, library, device, os, user_agent_string, verified, ja4_fingerprint, etc.

        # Check size if possible, but we'll try to load json directly.
        # If it's too large, we might need a streaming parser, but for 177MB requests.json() might struggle on small VMs.
        # Let's try requests.json(). If it fails, we need another strategy.
        data = r.json()

        rows = []
        for item in data:
            ja4 = item.get('ja4_fingerprint')
            if not ja4:
                continue

            # Construct description
            desc_parts = []
            if item.get('application'): desc_parts.append(item['application'])
            if item.get('library'): desc_parts.append(item['library'])
            if item.get('os'): desc_parts.append(item['os'])
            if item.get('device'): desc_parts.append(item['device'])
            if item.get('user_agent_string'): desc_parts.append(item['user_agent_string'])

            desc = " ".join([str(p) for p in desc_parts if p])

            # Determine risk level
            # User instruction: "verified= true as safe yes"
            is_verified = item.get('verified')
            risk_level = 'safe' if is_verified is True else 'info'

            rows.append({
                'ja4': ja4,
                'description': desc if desc else "Unknown Application",
                'source': 'JA4DB-Official',
                'risk_level': risk_level
            })

        print(f"  -> Found {len(rows)} signatures")
        return rows

    except Exception as e:
        print(f"  -> Error: {e}")
        return []

def download_threatfox():
    print("Downloading ThreatFox Database...")
    url = "https://threatfox.abuse.ch/export/csv/full/"
    try:
        r = requests.get(url)
        r.raise_for_status()

        # ThreatFox is ZIP compressed
        z = zipfile.ZipFile(io.BytesIO(r.content))
        # The file inside usually doesn't have a fixed name, take the first text file
        filename = z.namelist()[0]

        rows = []
        with z.open(filename) as f:
            content = f.read().decode('utf-8', errors='replace')
            lines = [l for l in content.splitlines() if not l.startswith('#')]

            reader = csv.reader(lines)
            for row in reader:
                if len(row) < 8: continue
                # Placeholder logic as confirmed in previous version
                pass

        return []

    except Exception as e:
        print(f"  -> Error: {e}")
        return []

def save_csv(rows):
    if not rows:
        print("No data to save.")
        return

    # --- ADDED CODE START ---
    # Ensure the directory exists before opening the file
    directory = os.path.dirname(OUTPUT_FILE)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")
    # --- ADDED CODE END --- 

    print(f"Saving {len(rows)} records to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['ja4', 'description', 'source', 'risk_level'])
        writer.writeheader()
        writer.writerows(rows)

if __name__ == "__main__":
    all_data = []
    all_data.extend(download_ja4plus())
    all_data.extend(download_ja4db_official())
    # all_data.extend(download_threatfox())

    save_csv(all_data)
