import requests
import hashlib
import os
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

def get_api_key():
    print(Fore.YELLOW + "\nThis project uses the VirusTotal Public API v3")
    print(Fore.YELLOW + "You need an API key from: https://www.virustotal.com/gui/user/apikey")
    return input(Fore.CYAN + "\n🔑 Enter your VirusTotal API Key: ").strip()

def scan_url(api_key, url):
    print(Fore.YELLOW + f"\n🔗 Scanning URL: {url}")
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}
    data = {"url": url}

    response = requests.post(endpoint, headers=headers, data=data)

    if response.status_code == 200:
        url_id = response.json()["data"]["id"]
        result = requests.get(f"{endpoint}/{url_id}", headers=headers).json()
        stats = result['data']['attributes']['last_analysis_stats']
        print(Fore.GREEN + f"🛡️ Analysis Results: {stats}")
    else:
        print(Fore.RED + "❌ Error:", response.text)

def scan_file(api_key, file_path):
    if not os.path.exists(file_path):
        print(Fore.RED + "❌ File does not exist.")
        return

    print(Fore.YELLOW + f"\n📦 Scanning File: {file_path}")
    endpoint = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}

    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post(endpoint, headers=headers, files=files)

    if response.status_code == 200:
        file_id = response.json()["data"]["id"]
        result = requests.get(f"{endpoint}/{file_id}", headers=headers).json()
        stats = result['data']['attributes']['last_analysis_stats']
        print(Fore.GREEN + f"🛡️ Analysis Results: {stats}")
    else:
        print(Fore.RED + "❌ Error:", response.text)

def scan_file_hash(api_key, file_path):
    if not os.path.exists(file_path):
        print(Fore.RED + "❌ File does not exist.")
        return

    print(Fore.YELLOW + f"\n🔍 Searching by File Hash (SHA-256) for: {file_path}")
    with open(file_path, "rb") as f:
        file_data = f.read()
        file_hash = hashlib.sha256(file_data).hexdigest()

    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    response = requests.get(endpoint, headers=headers)

    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        print(Fore.GREEN + f"🛡️ Analysis Results: {stats}")
    else:
        print(Fore.RED + "❌ Hash not found in VirusTotal database.")

def main():
    parser = argparse.ArgumentParser(description="VirusTotal API URL & File Scanner")
    parser.add_argument("--api-key", help="VirusTotal API Key")
    parser.add_argument("--url", help="Scan a URL")
    parser.add_argument("--file", help="Upload and scan a file")
    parser.add_argument("--hash", help="Scan a file using SHA-256 hash lookup")

    args = parser.parse_args()
    api_key = args.api_key or get_api_key()

    if args.url:
        scan_url(api_key, args.url)
    elif args.file:
        scan_file(api_key, args.file)
    elif args.hash:
        scan_file_hash(api_key, args.hash)
    else:
        while True:
            print(Fore.CYAN + "\nOptions:")
            print("1. Scan URL")
            print("2. Upload and Scan File")
            print("3. Check File via Hash")
            print("4. Exit")

            choice = input("Choose an option: ").strip()

            if choice == "1":
                url = input("Enter the URL: ").strip()
                scan_url(api_key, url)
            elif choice == "2":
                path = input("Enter file path: ").strip()
                scan_file(api_key, path)
            elif choice == "3":
                path = input("Enter file path to hash and scan: ").strip()
                scan_file_hash(api_key, path)
            elif choice == "4":
                print(Fore.YELLOW + "Exiting. Stay safe!")
                break
            else:
                print(Fore.RED + "Invalid option. Try again.")

if __name__ == "__main__":
    main()