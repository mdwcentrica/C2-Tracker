import argparse
import shodan
import time

def test_shodan_query(api_key, query_str):
   api = shodan.Shodan(api_key)
   try:
       print(f"\nTesting query: {query_str}")
       
       initial_response = api.search(query_str, page=1, limit=1, minify=False)
       total_available = initial_response.get('total', 0)
       print(f"\nTotal results available according to Shodan: {total_available}")
       
       total_results = []
       unique_ips = set()
       page = 1
       
       while len(total_results) < 1000:
           print(f"\nFetching page {page}...")
           response = api.search(query_str, page=page, limit=100, minify=False,
                               fields=['ip_str', 'port', 'location.country_name', 
                                      'org', 'isp', 'hostnames'])
           
           matches = response.get('matches', [])
           if not matches:
               break
               
           print(f"Found {len(matches)} results on page {page}")
           
           for match in matches:
               ip = match.get('ip_str', '')
               if ip and ip not in unique_ips:
                   unique_ips.add(ip)
                   total_results.append(match)
               if len(total_results) >= 1000:
                   break
           
           print(f"Unique IPs so far: {len(unique_ips)}")
           page += 1
           time.sleep(1)

       print(f"\nTotal unique IPs collected: {len(total_results)}")
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
       if hasattr(e, 'response'):
           print(f"Response status code: {e.response.status_code}")
       return False
   except Exception as e:
       print(f"\nUnexpected error: {str(e)}")
       return False

def main():
   parser = argparse.ArgumentParser(description='Test Shodan Query')
   parser.add_argument('--apikey', required=True, help='Shodan API Key')
   parser.add_argument('--query', required=True, help='Shodan query to test')
   args = parser.parse_args()
   test_shodan_query(args.apikey, args.query)

if __name__ == "__main__":
   main()
