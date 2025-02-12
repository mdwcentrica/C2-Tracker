import argparse
import shodan
import time

def test_shodan_query(api_key, query_str):
    """
    Test a single Shodan query and print all results with pagination
    """
    api = shodan.Shodan(api_key)
    try:
        print(f"\nTesting query: {query_str}")
        
        # Get total results count first
        initial_response = api.search(query_str, page=1, limit=1, minify=False)
        total_available = initial_response.get('total', 0)
        print(f"\nTotal results available according to Shodan: {total_available}")
        
        # Initialize empty list for all results and set for unique IPs
        total_results = []
        unique_ips = set()
        page = 1
        
        # Continue fetching pages until no more results or hit page 10
        while page <= 10:
            print(f"\nFetching page {page}...")
            try:
                response = api.search(query_str, page=page, limit=100, minify=False,
                                    fields=['ip_str', 'port', 'location.country_name', 
                                           'org', 'isp', 'hostnames'])
                
                matches = response.get('matches', [])
                if not matches:  # If no results in this page, we're done
                    print(f"No results found on page {page}, stopping pagination")
                    break
                
                # Only add results with new IPs
                for match in matches:
                    ip = match.get('ip_str', '')
                    if ip and ip not in unique_ips:
                        unique_ips.add(ip)
                        total_results.append(match)
                
                print(f"Found {len(matches)} results on page {page}")
                print(f"Unique IPs so far: {len(unique_ips)}")
                
                page += 1
                time.sleep(1)  # Rate limiting precaution
                
            except shodan.APIError as e:
                print(f"Error on page {page}: {str(e)}")
                break

        # Final results output
        print(f"\nFinal total unique IPs collected: {len(total_results)}")
        print("\nShowing all unique results:")
        for i, match in enumerate(total_results, 1):
            print(f"\nResult {i}:")
            print(f"IP: {match.get('ip_str', '')}")
            print(f"Port: {match.get('port', '')}")
            print(f"Country: {match.get('location', {}).get('country_name', '')}")
            print(f"Org: {match.get('org', '')}")
            print(f"ISP: {match.get('isp', '')}")
            print(f"Hostnames: {match.get('hostnames', [])}")
        
        return True
        
    except shodan.APIError as e:
        print(f"\nShodan API Error: {str(e)}")
        print(f"Error type: {type(e)}")
        if hasattr(e, 'response'):
            print(f"Response status code: {e.response.status_code}")
            print(f"Response headers: {e.response.headers}")
        return False
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        print(f"Error type: {type(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Test Shodan Query')
    parser.add_argument('--apikey', required=True, help='Shodan API Key')
    parser.add_argument('--query', required=True, help='Shodan query to test')
    
    args = parser.parse_args()
    test_shodan_query(args.apikey, args.query)

if __name__ == "__main__":
    main()
