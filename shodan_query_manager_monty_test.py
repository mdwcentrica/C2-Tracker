import json
import argparse
from datetime import datetime
import os
import logging
import time
import requests
import pandas as pd
import shodan

SHODAN_COUNT_URL = "https://api.shodan.io/shodan/host/count"
SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
RESULTS_PER_PAGE = 100
SLEEP_TIME = 2

class ShodanQueryManager:
    def __init__(self, api_key, project_label=None):
        """ Initialize Shodan Query Manager with pagination fixes. """
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s: %(message)s",
            filename="/home/azureuser/projects/Monty/logs/shodan_query.log"
        )

        self.api_key = api_key
        self.project_label = project_label
        self.api = shodan.Shodan(self.api_key)

    def get_total_results(self, query):
        """ Get total results for a query using Shodan's count endpoint. """
        params = {"key": self.api_key, "query": query}
        try:
            response = requests.get(SHODAN_COUNT_URL, params=params, verify=False)
            response.raise_for_status()
            return response.json().get("total", 0)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching total results: {e}")
            return 0

    def perform_query(self, query_item):
        """ Perform a paginated Shodan query. """
        query_str = query_item.get("query", "")
        malware_name = query_item.get("malware_name", query_str)
        tag = query_item.get("tag", "")
        today = datetime.now().strftime("%Y-%m-%d")

        total_results = self.get_total_results(query_str)
        if total_results == 0:
            logging.info(f"No results found for query: {query_str}")
            return pd.DataFrame()

        total_pages = (total_results // RESULTS_PER_PAGE) + (1 if total_results % RESULTS_PER_PAGE > 0 else 0)
        logging.info(f"Query: {query_str} | Total Results: {total_results} | Pages: {total_pages}")

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
                data = response.json()
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                logging.warning(f"Error processing page {page}: {e}")
                continue

            matches = data.get("matches", [])
            if not matches:
                logging.info(f"No results on Page {page}. Moving on.")
                continue

            for result in matches:
                try:
                    ip = result.get("ip_str", "")
                    if ip and ip not in unique_ips:
                        record = {
                            "ip": ip,
                            "query": query_str,
                            "malware_name": malware_name,
                            "tag": tag,
                            "port": result.get("port", ""),
                            "country": result.get("location", {}).get("country_name", ""),
                            "org": result.get("org", ""),
                            "isp": result.get("isp", ""),
                            "hostnames": ", ".join(result.get("hostnames", [])),
                            "first_seen": today,
                            "last_seen": today,
                            "projectlabel": self.project_label if self.project_label else "",
                        }
                        unique_ips[ip] = record
                        results.append(record)
                except Exception as e:
                    logging.warning(f"Skipping problematic IP entry: {e}")

            logging.info(f"Collected {len(unique_ips)} unique IPs so far for query: {query_str}")

            time.sleep(SLEEP_TIME)

        return pd.DataFrame(results)

    def run_queries(self, queries_file, output_dir):
        """ Run all queries from a JSON file and save results. """
        os.makedirs(output_dir, exist_ok=True)

        try:
            with open(queries_file, "r") as f:
                queries = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"Error loading queries: {e}")
            return

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        results_filename = os.path.join(output_dir, "shodan_results.csv")

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

def main():
    parser = argparse.ArgumentParser(description="Shodan Query Tool with Pagination Fix")
    parser.add_argument("--apikey", required=True, help="Shodan API Key")
    parser.add_argument("--queries", default="queries.json", help="Path to queries JSON file")
    parser.add_argument("--output", default="shodan_results", help="Output directory")
    parser.add_argument("--projectlabel", help="Optional project label for results")

    args = parser.parse_args()

    try:
        query_manager = ShodanQueryManager(args.apikey, args.projectlabel)
        query_manager.run_queries(args.queries, args.output)
    except Exception as e:
        logging.critical(f"Unexpected error: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
