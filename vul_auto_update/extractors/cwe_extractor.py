import os
import sys
import requests
import asyncio
import aiohttp
from time import time
from vul_auto_update.database.neo4j_manager import Neo4jManager

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

class CWEExtractor:
    def __init__(self):
        self.api_url = "https://cwe-api.mitre.org/api/v1"
        self.neo4j_manager = Neo4jManager()
        self.max_concurrency = 250
        self.retry_limit = 3

    # ecosystems
    def get_all_cwe_ids(self):
        try:
            url = f"{self.api_url}/cwe/weakness/all"
            response = requests.get(url)
            response.raise_for_status()
            weaknesses = response.json().get("Weaknesses", [])
            ids = [entry["ID"] for entry in weaknesses]
            print(f" Retrieved {len(ids)} CWE IDs.")
            return ids
        except requests.RequestException as e:
            print(f" Failed to get CWE IDs: {e}")
            return []


    # Fetch one CWE ID's data (sync version of fetch)
    def fetch_single_cwe(self, cwe_id):
        try:
            url = f"{self.api_url}/cwe/weakness/{cwe_id}"
            response = requests.get(url)
            response.raise_for_status()
            cwe_data_list = response.json().get("Weaknesses", [])
            results = []

            for item in cwe_data_list:
                results.append({
                    "cwe_id": item.get("ID"),
                    "name": item.get("Name"),
                    "description": item.get("Description", "No description available")
                })
                print(f"Fetched CWE: {item.get('ID')} - {item.get('Name')}")
            return results

        except requests.RequestException as e:
            print(f"[CWE-{cwe_id}] Failed to fetch: {e}")
            return []

    # Async version of fetch_single_cwe
    async def fetch(self, session, sem, cwe_id):
        async with sem:
            url = f"{self.api_url}/cwe/weakness/{cwe_id}"
            for attempt in range(self.retry_limit):
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            data = await response.json()
                            result = []
                            for item in data.get("Weaknesses", []):
                                result.append({
                                    "cwe_id": item.get("ID"),
                                    "name": item.get("Name"),
                                    "description": item.get("Description", "No description available")
                                })
                                print(f"Fetched CWE: {item.get('ID')} - {item.get('Name')}")
                            return result
                        else:
                            print(f"[CWE-{cwe_id}] Status: {response.status}")
                            return []
                except Exception as e:
                    print(f"[CWE-{cwe_id}] Exception: {e}")
                    await asyncio.sleep(2 ** attempt)
        return []

    # Fetch all CWE entries as JSON
    async def fetch_all_cwes_json(self, cwe_ids):
        results = []
        sem = asyncio.Semaphore(self.max_concurrency)
        async with aiohttp.ClientSession() as session:
            tasks = [asyncio.create_task(self.fetch(session, sem, cid)) for cid in cwe_ids]
            responses = await asyncio.gather(*tasks)
            for r in responses:
                results.extend(r)
        return results

    # Optional custom query
    def fetch_cwe_by_name(self, name_query):
        # This is a dummy to keep structure parity with fetch_osv_data()
        print(f"Searching CWEs for keyword: {name_query} (not implemented)")
        return []

    # Save results to Neo4j
    def store_cwe_to_db(self, cwe_list):
        for cwe in cwe_list:
            self.neo4j_manager.upsert_cwe(
                cwe_id=cwe['cwe_id'],
                name=cwe['name'],
                description=cwe['description']
            )
        self.neo4j_manager.close()

    def fetch_cwe_data(self):
        cwe_ids = self.get_all_cwe_ids()
        if not cwe_ids:
            return []

        print(f"[INFO] Fetching full CWE data for {len(cwe_ids)} IDs...")
        return asyncio.run(self.fetch_all_cwes_json(cwe_ids))

#Test Block
if __name__ == "__main__":
    start = time()
    extractor = CWEExtractor()

    # Test get_all_cwe_ids()
    sample_ids = extractor.get_all_cwe_ids()  # Just a few for testing
    print(len(sample_ids))
    # print(f"Sample CWE IDs: {sample_ids}")

    # Test fetch_single_cwe() on one ID
    print("\n Testing fetch_single_cwe on CWE-79:")
    sample_single = extractor.fetch_single_cwe("79")
    print(sample_single[:1])  # Show just one result

    # Test async fetch_all_cwes_json() on a few IDs
    print("\n Testing fetch_all_cwes_json on sample:")
    results = asyncio.run(extractor.fetch_all_cwes_json(sample_ids))
    print(f" Total CWE entries fetched: {len(results)}")

    # Test storing (comment out if Neo4j isn't running)
    print("\n Storing to Neo4j:")
    extractor.store_cwe_to_db(results)

    print(f"\n Test run complete in {time() - start:.2f} seconds")
