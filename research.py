import requests
import json
import zipfile
import os

# Endpoint URL
MITREURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

def fetch_mitre_attack_data(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()  # Raises HTTPError for 4xx/5xx

        data = response.json()
        return data

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return None





# NVD Feeds
NVD_FEEDS = {
    "recent": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip",
    "modified": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip",
    "2026": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.zip",
}

BASE_DIR = "/Users/abhipsa/Documents/VulnGuard AI/base"
EXTRACT_DIR = "/Users/abhipsa/Documents/VulnGuard AI/extract"

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)


def download_feed(url, output_path):
    response = requests.get(url, stream=True, timeout=60)
    response.raise_for_status()

    with open(output_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)


def extract_zip(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_to)


def download_all_feeds(feeds):
    for feed_name, feed_url in feeds.items():
        print(f"Downloading {feed_name} feed...")

        zip_file_path = os.path.join(BASE_DIR, f"{feed_name}.zip")
        download_feed(feed_url, zip_file_path)

        print(f"Extracting {feed_name} feed...")
        extract_zip(zip_file_path, EXTRACT_DIR)

        print(f"{feed_name} feed processed successfully\n")

if __name__ == "__main__":
    mitre_data = fetch_mitre_attack_data(MITREURL)

    if mitre_data:
        print("Data fetched successfully!")
        print(f"Top-level keys: {mitre_data.keys()}")

        # Optional: save to file
        with open("/Users/abhipsa/Documents/VulnGuard AI/enterprise_attack.json", "w") as f:
            json.dump(mitre_data, f, indent=2)

        print("JSON saved as enterprise_attack.json")

    download_all_feeds(NVD_FEEDS)