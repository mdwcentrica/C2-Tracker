import argparse
import requests
import time

SHODAN_COUNT_URL = "https://api.shodan.io/shodan/host/count"
SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
RESULTS_PER_PAGE = 100  # Shodan returns up to 100 results per page
SLEEP_TIME = 2  # Adjust sleep to avoid API rate limits

def get_total_results(api_key, query):
    """ Get total results count from Shodan """
    params = {"key": api_key, "query": query}
    response = requests.get(SHODAN_COUNT_URL, params=params)

    if response.status_code == 200:
        return response.json().get("total", 0)
    
    print(f"Error {response.status_code}: {response.json().get('error', 'Unknown error')}")
    return 0

def shodan_search(api_key, query):
    """ Perform paginated Shodan search and collect unique results """
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

        response = requests.get(SHODAN_SEARCH_URL, params=params)
        
        if response.status_code != 200:
            print(f"Error {response.status_code}: {response.json().get('error', 'Unknown error')}")
            break

        data = response.json()
        matches = data.get("matches", [])

        if not matches:
            print("No more results available.")
            break

        for match in matches:
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

        print(f"Collected {len(unique_ips)} unique IPs so far.")
        
        # Stop if this was the last page of results
        if len(matches) < RESULTS_PER_PAGE:
            break

        time.sleep(SLEEP_TIME)  # Respect API limits

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
