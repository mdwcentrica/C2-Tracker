import argparse
import requests
import time
import json

SHODAN_COUNT_URL = "https://api.shodan.io/shodan/host/count"
SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
RESULTS_PER_PAGE = 100  # Max results per page
SLEEP_TIME = 2  # Sleep time to respect API limits

def get_total_results(api_key, query):
    """ Get the total number of results for a query using Shodan's count endpoint. """
    params = {"key": api_key, "query": query}
    try:
        response = requests.get(SHODAN_COUNT_URL, params=params)
        response.raise_for_status()
        return response.json().get("total", 0)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching total results: {e}")
        return 0

def shodan_search(api_key, query):
    """ Perform paginated Shodan search while collecting unique IPs. """
    unique_ips = {}
    total_results = get_total_results(api_key, query)
    
    if total_results == 0:
        print("No results found.")
        return

    total_pages = (total_results // RESULTS_PER_PAGE) + (1 if total_results % RESULTS_PER_PAGE > 0 else 0)
    print(f"Total Results: {total_results}")
    print(f"Paging through {total_pages} pages...\n")

    for page in range(1, total_pages + 1):
        print(f"Fetching Page {page}/{total_pages}...")

        params = {
            "key": api_key,
            "query": query,
            "page": page
        }

        try:
            response = requests.get(SHODAN_SEARCH_URL, params=params)
            response.raise_for_status()  # Raise an error for bad responses
            data = response.json()
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            print(f"Error processing page {page}: {e}")
            continue  # Skip this page and move to the next

        matches = data.get("matches", [])

        if not matches:
            print(f"⚠️ No data returned for Page {page}. Moving on.")
            continue

        for match in matches:
            try:
                ip = match.get("ip_str", "")
                if ip and ip not in unique_ips:  # Store first occurrence only
                    unique_ips[ip] = {
                        "IP": ip,
                        "Port": match.get("port", ""),
                        "Country": match.get("location", {}).get("country_name", ""),
                        "Org": match.get("org", ""),
                        "ISP": match.get("isp", ""),
                        "Hostnames": match.get("hostnames", [])
                    }
            except Exception as ip_error:
                print(f"Skipping problematic IP entry: {ip_error}")
                continue  # Skip this IP and move to the next

        print(f"Collected {len(unique_ips)} unique IPs so far.")

        time.sleep(SLEEP_TIME)  # Respect API rate limits

    print("\nFinal Results:")
    print(f"Total Unique IPs Found: {len(unique_ips)}\n")

    for details in unique_ips.values():
        print(f"IP: {details['IP']}")
        print(f"Port: {details['Port']}")
        print(f"Country: {details['Country']}")
        print(f"Org: {details['Org']}")
        print(f"ISP: {details['ISP']}")
        print(f"Hostnames: {details['Hostnames']}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shodan API Search Script")
    parser.add_argument("api_key", type=str, help="Your Shodan API Key")
    parser.add_argument("query", type=str, help="Search query for Shodan")
    args = parser.parse_args()

    shodan_search(args.api_key, args.query)
