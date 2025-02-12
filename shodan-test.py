import argparse
import shodan
import time

def test_shodan_query(api_key, query_str):
    api = shodan.Shodan(api_key)
    try:
        total_results = []
        unique_ips = set()
        
        # Get first page to check total available
        initial_results = api.search(query_str, page=1, limit=100, minify=False)
        total_available = initial_results.get('total', 0)
        print(f"Total results available: {total_available}")
        
        # Process first page results
        for match in initial_results.get('matches', []):
            ip = match.get('ip_str', '')
            if ip and ip not in unique_ips:
                unique_ips.add(ip)
                total_results.append(match)
        
        print(f"Page 1: Found {len(initial_results.get('matches', []))} results, {len(unique_ips)} unique IPs")
        
        # Get remaining pages up to 1000 results or no more results
        current_page = 2
        while len(total_results) < 1000 and current_page <= 10:
            time.sleep(1)  # Rate limit
            try:
                print(f"\nGetting page {current_page}")
                results = api.search(query_str, page=current_page, limit=100, minify=False)
                matches = results.get('matches', [])
                
                if not matches:
                    print("No more results available")
                    break
                    
                for match in matches:
                    ip = match.get('ip_str', '')
                    if ip and ip not in unique_ips:
                        unique_ips.add(ip)
                        total_results.append(match)
                        if len(total_results) >= 1000:
                            break
                
                print(f"Page {current_page}: Found {len(matches)} results, Total unique IPs: {len(unique_ips)}")
                current_page += 1
                
            except shodan.APIError as e:
                print(f"Error on page {current_page}: {str(e)}")
                break

        print(f"\nFinal Results:")
        print(f"Total unique IPs collected: {len(unique_ips)}")
        
        for i, match in enumerate(total_results, 1):
            print(f"\nResult {i}:")
            print(f"IP: {match.get('ip_str', '')}")
            print(f"Port: {match.get('port', '')}")
            print(f"Country: {match.get('location', {}).get('country_name', '')}")
            print(f"Org: {match.get('org', '')}")
            print(f"ISP: {match.get('isp', '')}")
            print(f"Hostnames: {match.get('hostnames', [])}")

    except Exception as e:
        print(f"Error: {str(e)}")
        return False

    return True

def main():
    parser = argparse.ArgumentParser(description='Test Shodan Query')
    parser.add_argument('--apikey', required=True, help='Shodan API Key')
    parser.add_argument('--query', required=True, help='Shodan query to test')
    args = parser.parse_args()
    test_shodan_query(args.apikey, args.query)

if __name__ == "__main__":
    main()
