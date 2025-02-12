import argparse
import requests
import time

SHODAN_API_URL = "https://api.shodan.io/shodan/host/search"

def shodan_search(api_key, query):
    unique_ips = set()
    page = 1
    total_results = 0

    while True:
        params = {
            "key": api_key,
            "query": query,
            "page": page
        }

        response = requests.get(SHODAN_API_URL, params=params)

        if response.status_code != 200:
            print(f"Error {response.status_code}: {response.json().get('error', 'Unknown error')}")
            break

        data = response.json()

        if "matches" not in data:
            print("No results found.")
            break

        if page == 1:
            total_results = data.get("total", 0)
            print(f"Total Results: {total_results}")
            total_pages = (total_results // 100) + (1 if total_results % 100 > 0 else 0)
            print(f"Total Pages: {total_pages}")

        for result in data["matches"]:
            unique_ips.add(result["ip_str"])

        print(f"Page {page} processed. Total unique IPs so far: {len(unique_ips)}")

        if len(data["matches"]) < 100:  # Last page reached
            break

        page += 1
        time.sleep(1)  # Rate limiting to avoid API bans

    print("\nFinal Results:")
    print(f"Total Unique IPs Found: {len(unique_ips)}")
    for ip in unique_ips:
        print(ip)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shodan API Search Script")
    parser.add_argument("api_key", type=str, help="Your Shodan API Key")
    parser.add_argument("query", type=str, help="Search query for Shodan")
    args = parser.parse_args()

    shodan_search(args.api_key, args.query)
