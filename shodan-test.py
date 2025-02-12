import argparse
import shodan

def test_shodan_query(api_key, query_str):
    """
    Test a single Shodan query and print raw response for debugging
    """
    api = shodan.Shodan(api_key)
    try:
        # Print the query we're testing
        print(f"\nTesting query: {query_str}")
        
        # Attempt the search
        print("\nAttempting API call...")
        response = api.search(query_str, page=1, limit=1)
        
        # Print raw response details
        print("\nResponse details:")
        print(f"Total results reported: {response.get('total', 0)}")
        print(f"Response type: {type(response)}")
        
        # Print first few matches if they exist
        matches = response.get('matches', [])
        print(f"\nNumber of matches in response: {len(matches)}")
        
        if matches:
            print("\nFirst match details:")
            for key, value in matches[0].items():
                print(f"{key}: {value}")
        
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
