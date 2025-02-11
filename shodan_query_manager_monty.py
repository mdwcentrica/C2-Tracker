import json
import argparse
from datetime import datetime
import os
import logging
import time

import numpy as np
import pandas as pd
import shodan

class ShodanQueryManager:
    def __init__(self, api_key, ips_file='seen_ips.csv', project_label=None):
        """
        Initialize Shodan Query Manager with IP tracking

        :param api_key: Shodan API key
        :param ips_file: CSV file to track seen IPs
        :param project_label: Optional project label for results
        """
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s',
            filename='shodan_query.log'
        )

        self.api_key = api_key
        self.ips_file = ips_file
        self.project_label = project_label
        self.api = self.initialize_shodan_client()

        # Subscription-aware result limits
        self.subscription_limits = {
            'basic': {
                'total_results_limit': 100,
                'pages_limit': 1
            },
            'freelancer': {
                'total_results_limit': 1000,
                'pages_limit': 10
            },
            'corporate': {
                'total_results_limit': 100000,
                'pages_limit': 100
            }
        }
        self.current_subscription = 'enterprise'

    def initialize_shodan_client(self):
        """
        Initialize Shodan API client with comprehensive error handling
        """
        try:
            api = shodan.Shodan(self.api_key)
            # Test API key and determine subscription level
            account_info = api.info()

            if account_info.get('plan', '').lower() == 'freelancer':
                self.current_subscription = 'freelancer'
                logging.info("Detected Freelancer subscription")
            elif account_info.get('plan', '').lower() == 'enterprise':
                self.current_subscription = 'corporate'
                logging.info("Detected Corporate subscription")
            else:
                logging.info("Detected Basic subscription")

            return api
        except shodan.APIError as e:
            logging.error(f"Shodan API Error during initialization: {e}")
            raise

    def load_or_create_seen_ips(self):
        """
        Load existing seen IPs or create a new DataFrame

        :return: DataFrame with IP tracking information
        """
        try:
            # Define column types for efficiency
            dtypes = {
                'ip': str,
                'first_seen': str,
                'last_seen': str,
                'times_seen': int,
                'malware_names': str,
                'tags': str
            }

            # If file exists, load it
            if os.path.exists(self.ips_file):
                df = pd.read_csv(self.ips_file, dtype=dtypes)
                return df

            # Create new DataFrame if file doesn't exist
            columns = list(dtypes.keys())
            return pd.DataFrame(columns=columns)

        except Exception as e:
            logging.error(f"Error loading/creating seen IPs: {e}")
            return pd.DataFrame(columns=['ip', 'first_seen', 'last_seen', 'times_seen', 'malware_names', 'tags'])

    def update_seen_ips(self, new_results_df, existing_ips_df):
        """
        Update seen IPs with new results

        :param new_results_df: DataFrame of new Shodan query results
        :param existing_ips_df: DataFrame of previously seen IPs
        :return: Updated DataFrame of seen IPs, Set of previously seen IPs
        """
        today = datetime.now().strftime('%Y-%m-%d')
        previously_seen_ips = set(existing_ips_df['ip'].values)

        # Combine existing and new IPs, tracking unique entries
        for _, row in new_results_df.iterrows():
            ip = row['ip']
            malware_name = row['malware_name']
            tags = row['tag'].split(',') if pd.notna(row['tag']) else []

            # Check if IP exists in existing DataFrame
            ip_exists = existing_ips_df['ip'].eq(ip)
            print(f"ip exists ${ip_exists}")

            if ip_exists.any():
                # Update existing IP entry
                idx = ip_exists[ip_exists].index[0]
                existing_ips_df.loc[idx, 'last_seen'] = today
                existing_ips_df.loc[idx, 'times_seen'] += 1

                # Update malware names and tags, avoiding duplicates
                current_malware = existing_ips_df.loc[idx, 'malware_names'].split(',') if pd.notna(existing_ips_df.loc[idx, 'malware_names']) else []
                current_tags = existing_ips_df.loc[idx, 'tags'].split(',') if pd.notna(existing_ips_df.loc[idx, 'tags']) else []

                if malware_name not in current_malware:
                    current_malware.append(malware_name)
                for tag in tags:
                    if tag and tag not in current_tags:
                        current_tags.append(tag)

                existing_ips_df.loc[idx, 'malware_names'] = ','.join(current_malware)
                existing_ips_df.loc[idx, 'tags'] = ','.join(current_tags)
            else:
                # Add new IP entry
                new_entry = pd.DataFrame({
                    'ip': [ip],
                    'first_seen': [today],
                    'last_seen': [today],
                    'times_seen': [1],
                    'malware_names': [malware_name],
                    'tags': [','.join(tags)]
                })
                existing_ips_df = pd.concat([existing_ips_df, new_entry], ignore_index=True)

        return existing_ips_df, previously_seen_ips

    def load_queries(self, queries_file='/home/azureuser/projects/Monty/queries/shodan/formatted/formatted_shodan_queries'):
        """
        Load Shodan queries from JSON file with robust error handling
        """
        try:
            with open(queries_file, 'r') as f:
                queries = json.load(f)

            # Validate query structure
            for query in queries:
                if not all(key in query for key in ['query', 'tag', 'malware_name', 'active']):
                    logging.warning(f"Invalid query structure: {query}")

            active_queries = [q for q in queries if q.get('active', '').lower() == 'yes']
            return active_queries
        except FileNotFoundError:
            logging.error(f"Queries file not found")
            return []
        except json.JSONDecodeError:
            logging.error("Invalid JSON in queries file")
            return []

    def determine_result_limits(self):
        """
        Dynamically determine result limits based on subscription
        """
        limits = self.subscription_limits[self.current_subscription]
        return limits['total_results_limit'], limits['pages_limit']

    def perform_query(self, query_item):
        """
        Perform Shodan query with subscription-aware result handling

        :param query_item: Dictionary containing query details
        :return: Pandas DataFrame of results
        """
        query_str = query_item.get('query', '')
        malware_name = query_item.get('malware_name', query_str)
        tag = query_item.get('tag', '')
        today = datetime.now().strftime('%Y-%m-%d')

        total_results_limit, pages_limit = self.determine_result_limits()

        results = []
        ip_results = {}  # Dictionary to track results by IP
        try:
            # Iterate through pages based on subscription
            for page in range(1, pages_limit + 1):
                try:
                    page_results = self.api.search(
                        query_str,
                        page=page,
                        limit=min(1000, total_results_limit // pages_limit)
                    )

                    page_matches = page_results.get('matches', [])

                    # Split tags into separate columns
                    tags = tag.split(',')[:5]  # Take up to 5 tags
                    tags.extend([''] * (5 - len(tags)))  # Pad with empty strings if less than 5

                    # Process each result
                    for result in page_matches:
                        ip = result.get('ip_str', '')
                        
                        # Convert Shodan timestamp to date
                        shodan_timestamp = result.get('timestamp', '')
                        first_seen = datetime.strptime(shodan_timestamp.split('.')[0], '%Y-%m-%dT%H:%M:%S').strftime('%Y-%m-%d') if shodan_timestamp else today
                        
                        # Get hostnames
                        hostnames = result.get('hostnames', [])
                        
                        if ip in ip_results:
                            # Update existing IP entry
                            existing = ip_results[ip]
                            # Update first_seen if this result is older
                            if first_seen < existing['first_seen']:
                                existing['first_seen'] = first_seen
                            # Add new hostnames
                            existing['all_hostnames'].update(hostnames)
                        else:
                            # Create new IP entry
                            ip_results[ip] = {
                                'ip': ip,
                                'query': query_str,
                                'malware_name': malware_name,
                                'tag': tag,
                                'tag1': tags[0],
                                'tag2': tags[1],
                                'tag3': tags[2],
                                'tag4': tags[3],
                                'tag5': tags[4],
                                'all_hostnames': set(hostnames),
                                'port': result.get('port', ''),
                                'country': result.get('location', {}).get('country_name', ''),
                                'org': result.get('org', ''),
                                'isp': result.get('isp', ''),
                                'first_seen': first_seen,
                                'last_seen': today,
                                'projectlabel': self.project_label if self.project_label else '',
                                'labelcolour': '#0020FF',
                                'pattern type': 'stix',  
                                'pattern': f"[ipv4-addr:value = '{ip}']",  
                                'main observable type': 'IPv4-Addr'  
                            }

                    # Break if no more results
                    if len(page_matches) < 1000:
                        break

                except shodan.APIError as page_error:
                    logging.warning(f"Error fetching page {page} for query '{query_str}': {page_error}")
                    break

                # Respectful API usage
                time.sleep(1)

            # Convert IP results to list format
            for ip_data in ip_results.values():
                # Convert hostname set to list and process
                hostnames = list(ip_data.pop('all_hostnames'))
                # Add hostname fields
                ip_data['hostname'] = ','.join(hostnames)  # All hostnames comma-separated
                # Add individual hostname fields
                for i in range(3):
                    ip_data[f'hostname{i+1}'] = hostnames[i] if i < len(hostnames) else ''
                results.append(ip_data)

            # Convert to DataFrame
            results_df = pd.DataFrame(results)
            return results_df

        except shodan.APIError as e:
            logging.error(f"API Error for query '{query_str}': {e}")
            return pd.DataFrame()
        except Exception as e:
            logging.error(f"Unexpected error processing query '{query_str}': {e}")
            return pd.DataFrame()

    def run_queries(self, queries_file='formatted_shodan_queries.json', output_dir='queries/shodan/formatted/'):
        """
        Run Shodan queries, track IPs, and save results
        """
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Load queries
        queries = self.load_queries(queries_file)

        # Load existing seen IPs
        seen_ips_df = self.load_or_create_seen_ips()

        # Prepare output filename
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        results_filename = os.path.join(output_dir, f'shodan_results_monty.csv')
        ips_filename = self.ips_file

        # Collect and process results
        all_results_df = pd.DataFrame()
        for query_item in queries:
            query_results_df = self.perform_query(query_item)
            all_results_df = pd.concat([all_results_df, query_results_df], ignore_index=True)

        # Update seen IPs and get set of previously seen IPs
        updated_seen_ips_df, previously_seen_ips = self.update_seen_ips(all_results_df, seen_ips_df)

        # Filter out previously seen IPs from results
        #new_results_df = all_results_df[~all_results_df['ip'].isin(previously_seen_ips)]
        new_results_df = all_results_df.copy()

        # Save results and updated IP tracking
        try:
            # Save new results only
            if not new_results_df.empty:
                # Save to original location
                new_results_df.to_csv(results_filename, index=False)
                logging.info(f"New results written to {results_filename}")
                print(f"New results saved to {results_filename}")
                
                # Save to additional location
                additional_dir = '../projects/Monty/data/shodan/'
                os.makedirs(additional_dir, exist_ok=True)
                additional_filename = os.path.join(additional_dir, f'shodan_results.csv')
                new_results_df.to_csv(additional_filename, index=False)
                logging.info(f"New results also written to {additional_filename}")
                print(f"New results also saved to {additional_filename}")
            else:
                logging.info("No new results to save")
                print("No new results found")

            # Save updated seen IPs
            updated_seen_ips_df.to_csv(ips_filename, index=False)
            logging.info(f"Updated seen IPs written to {ips_filename}")

        except Exception as e:
            logging.error(f"Error saving results or IP tracking: {e}")

        return new_results_df, updated_seen_ips_df

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Shodan Query Tool')
    parser.add_argument('--apikey', required=True, help='Shodan API Key')
    parser.add_argument('--queries', default='queries.json', help='Path to queries JSON file')
    parser.add_argument('--output', default='shodan_results', help='Output directory')
    parser.add_argument('--ipsfile', default='seen_ips.csv', help='Path to seen IPs tracking file')
    parser.add_argument('--projectlabel', help='Optional project label for results')

    args = parser.parse_args()

    try:
        # Initialize and run queries
        query_manager = ShodanQueryManager(args.apikey, args.ipsfile, args.projectlabel)
        query_manager.run_queries(args.queries, args.output)

    except Exception as e:
        logging.critical(f"Unexpected error in main execution: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
