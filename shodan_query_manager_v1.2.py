import json
import argparse
from datetime import datetime
import os
import logging
import time
import requests
import pandas as pd
import shodan
from dotenv import load_dotenv  # Handles API key loading from a file

SHODAN_COUNT_URL = "https://api.shodan.io/shodan/host/count"
SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
RESULTS_PER_PAGE = 100
SLEEP_TIME = 2

class ShodanQueryManager:
    def __init__(self, api_key):
        """ Initialize Shodan Query Manager with enhanced logging and error handling. """
        log_file = "/home/azureuser/projects/Monty/logs/shodan_query.log"
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s: %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()  # Print logs to console live
            ]
        )

        self.api_key = api_key
        self.api = shodan.Shodan(self.api_key)

    def get_total_results(self, query):
        """ Get total results for a query using Shodan's count endpoint. """
        params = {"key": self.api_key, "query": query}
        try:
            logging.info(f"Fetching total result count for query: {query}")
            response = requests.get(SHODAN_COUNT_URL, params=params, verify=False)
            response.raise_for_status()
            total = response.json().get("total", 0)
            logging.info(f"Total results for query '{query}': {total}")
            return total
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching total results for query '{query}': {e}")
            return 0

    def perform_query(self, query_item):
        """ Perform a paginated Shodan query with improved JSON handling. """
        query_str = query_item.get("query", "")
        malware_name = query_item.get("malware_name", query_str)
        tags = query_item.get("tag", "").split(",")
        tags = [t.strip() for t in tags if t.strip()]  # Clean tag list
        today = datetime.now().strftime("%Y-%m-%d")

        logging.info(f"Starting query: {query_str} | Malware: {malware_name}")

        total_results = self.get_total_results(query_str)
        if total_results == 0:
            logging.info(f"No results found for query: {query_str}")
            return pd.DataFrame()

        total_pages = (total_results // RESULTS_PER_PAGE) + (1 if total_results % RESULTS_PER_PAGE > 0 else 0)
        logging.info(f"Query: {query_str} | Total Results: {total_results} | Pages to Fetch: {total_pages}")

        results = []
        unique_ips = {}

        for page in range(1, total_pages + 1):
            logging.info(f"Fetching Page {page}/{total_pages} for query: {query_str}...")

            params = {
                "key": self.api_key,
                "query": query_str,
                "page": page
            }

            try:
                response = requests.get(SHODAN_SEARCH_URL, params=params, verify=False)
                response.raise_for_status()
                
                # Fix malformed JSON responses
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    logging.error(f"JSON Decode Error on Page {page} for query '{query_str}'. Skipping page.")
                    continue

            except requests.exceptions.RequestException as e:
                logging.warning(f"Error processing page {page} for query '{query_str}': {e}")
                continue

            matches = data.get("matches", [])
            if not matches:
                logging.info(f"No results on Page {page} for query '{query_str}'. Moving on.")
                continue

            for result in matches:
                try:
                    ip = result.get("ip_str", "")
                    if ip and ip not in unique_ips:
                        hostnames = result.get("hostnames", [])
                        hostnames = [h.strip() for h in hostnames if h.strip()]  # Clean hostnames

                        record = {
                            "ip": ip,
                            "query": query_str,
                            "malware_name": malware_name,
                            "tag": ",".join(tags),
                            "tag1": tags[0] if len(tags) > 0 else "",
                            "tag2": tags[1] if len(tags) > 1 else "",
                            "tag3": tags[2] if len(tags) > 2 else "",
                            "tag4": tags[3] if len(tags) > 3 else "",
                            "tag5": tags[4] if len(tags) > 4 else "",
                            "port": result.get("port", ""),
                            "country": result.get("location", {}).get("country_name", ""),
                            "org": result.get("org", ""),
                            "isp": result.get("isp", ""),
                            "first_seen": today,
                            "last_seen": today,
                            "projectlabel": "CTI-IOA",
                            "labelcolour": "#0020FF",
                            "pattern type": "stix",
                            "pattern": f"[ipv4-addr:value = '{ip}']",  # Correctly uses dynamic IP
                            "main observable type": "IPv4-Addr",
                            "hostname": hostnames[0] if len(hostnames) > 0 else "",
                            "hostname1": hostnames[1] if len(hostnames) > 1 else "",
                            "hostname2": hostnames[2] if len(hostnames) > 2 else "",
                            "hostname3": hostnames[3] if len(hostnames) > 3 else "",
                        }
                        unique_ips[ip] = record
                        results.append(record)
                except Exception as e:
                    logging.warning(f"Skipping problematic IP entry for query '{query_str}': {e}")

            logging.info(f"Page {page} processed: Collected {len(unique_ips)} unique IPs so far for query '{query_str}'.")

            time.sleep(SLEEP_TIME)

        return pd.DataFrame(results)

    def run_queries(self, queries_file, output_dir, output_file):
        """ Run all queries from a JSON file and save results. """
        os.makedirs(output_dir, exist_ok=True)

        logging.info(f"Loading queries from file: {queries_file}")
        try:
            with open(queries_file, "r") as f:
                queries = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"Error loading queries: {e}")
            return

        logging.info(f"Loaded {len(queries)} queries from {queries_file}")
        results_filename = os.path.join(output_dir, output_file)

        all_results_df = pd.DataFrame()

        for query_item in queries:
            query_results_df = self.perform_query(query_item)
            all_results_df = pd.concat([all_results_df, query_results_df], ignore_index=True)

        if not all_results_df.empty:
            all_results_df.to_csv(results_filename, index=False)
            logging.info(f"Results saved to {results_filename}")
            print(f"Results saved to {results_filename}")
        else:
            logging.info("No results to save.")

def load_api_key(file_path):
    """ Load API key from a file """
    try:
        with open(file_path, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        logging.error(f"API key file not found: {file_path}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Shodan Query Tool with API Key File Support")
    parser.add_argument("--apikey", help="Shodan API Key (optional, will override file)")
    parser.add_argument("--apikeyfile", help="Path to API Key File", default=".shodan_api_key")
    parser.add_argument("--queries", default="queries.json", help="Path to queries JSON file")
    parser.add_argument("--outputdir", default="shodan_results", help="Output directory")
    parser.add_argument("--outputfile", default="shodan_results.csv", help="Output CSV file")

    args = parser.parse_args()

    # Load API key from file if not provided as an argument
    api_key = args.apikey if args.apikey else load_api_key(args.apikeyfile)

    logging.info("Script starting...")
    try:
        query_manager = ShodanQueryManager(api_key)
        query_manager.run_queries(args.queries, args.outputdir, args.outputfile)
    except Exception as e:
        logging.critical(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
