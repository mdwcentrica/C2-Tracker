import argparse
import requests
import time

SHODAN_API_URL = "https://api.shodan.io/shodan/host/search"

def shodan_search(api_key, query):
    unique_ips = set()
    page = 1
    total_results = 0
    results_per_page = 100  # Default Shodan page size

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

        if page == 1:  # Extract total results on the first page
            total_results = data.get("total", 0)
            total_pages = (total_results // results_per_page) + (1 if total_results % results_per_page > 0 else 0)
            print(f"Total Results: {total_results}")
            print(f"Total Pages: {total_pages}")

        if "matches" not in data or not data["matches"]:
            print("No more results available.")
            break

        for result in data["matches"]:
            unique_ips.add(result["ip_str"])

        print(f"Processed Page {page}. Total unique IPs collected: {len(unique_ips)}")

        # Check if we've reached the last page
        if len(data["matches"]) < results_per_page:
            break

        page += 1
        time.sleep(1)  # Avoid hitting API rate limits

    print("\nFinal Results:")
    print(f"Total Unique IPs Found: {len(unique_ips)}")
    for ip in sorted(unique_ips):
        print(ip)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shodan API Search Script")
    parser.add_argument("api_key", type=str, help="Your Shodan API Key")
    parser.add_argument("query", type=str, help="Search query for Shodan")
    args = parser.parse_args()

    shodan_search(args.api_key, args.query)
