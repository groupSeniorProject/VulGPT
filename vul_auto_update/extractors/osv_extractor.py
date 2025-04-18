import sys
import os
import requests
import asyncio
import aiohttp
import random
from time import time
from vul_auto_update.database.neo4j_manager import Neo4jManager
from vul_auto_update.config.config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

class OSVExtractor:
    def __init__(self):
        self.api_url = "https://api.osv.dev/v1/vulns"
        self.bucket_url = "https://www.googleapis.com/storage/v1/b/osv-vulnerabilities/o"
        self.neo4j_manager = Neo4jManager()
        self.max_concurrency = 250
        self.retry_limit = 3

    # returns a list of all osv ids from a specific ecosystem folder
    async def fetch_all_gcs_objects(self, prefix, headers=None):
        params = {
            "delimiter": "/",
            "prefix": prefix,
            "fields": "items(kind,mediaLink,metadata,name,size,updated),kind,prefixes,nextPageToken"
        }

        all_items = []
        async with aiohttp.ClientSession() as session:
            while True:
                response = await session.get(self.bucket_url, params=params, headers=headers)
                data = await response.json()
                items = data.get('items', [])
                for item in items:
                    if item['name'] != 'all.zip':
                        name = item['name']
                        clean_name = name.split('/')[-1].replace('.json', '')
                        all_items.append(clean_name)
                next_token = data.get('nextPageToken')
                if not next_token:
                    break
                params['pageToken'] = next_token
        return all_items

    # returns a list of ecosystem
    async def fetch_all_ecosystems(self, headers=None):
        params = {
            "delimiter": "/",
            "prefix": "",
            "fields": "items(kind,mediaLink,metadata,name,size,updated),kind,prefixes,nextPageToken"
        }

        all_prefixes = []
        async with aiohttp.ClientSession() as session:
            while True:
                response = await session.get(self.bucket_url, params=params, headers=headers, ssl=False)
                data = await response.json()
                prefixes = data.get('prefixes', [])
                all_prefixes.extend(prefixes)
                next_token = data.get('nextPageToken')
                if not next_token:
                    break
                params['pageToken'] = next_token
        return all_prefixes

    # takes in list of ecosystems, returns a unique list of all osv IDs
    async def get_unique_list(self, all_ecosystems, bucket_url, headers=None):
        total = 0
        all_objects = {}

        tasks = []
        for ecosystem in all_ecosystems:
            tasks.append(asyncio.create_task(self.fetch_all_gcs_objects(bucket_url, ecosystem, headers)))
        results = await asyncio.gather(*tasks)

        for i, ecosystem in enumerate(all_ecosystems):
            clean_name = ecosystem.replace('/', '')
            # ecosystem = "CRAN/"
            all_objects[clean_name] = results[i]
            print(f"{clean_name}: {len(all_objects[clean_name])}")
            total+=len(all_objects[clean_name])

        combined_list = []
        for value in all_objects.values():
            combined_list.extend(value)

        unique_list = list(set(combined_list))
        return unique_list

    # fetches a single vuln JSON from the osv API
    async def fetch(self, session: aiohttp.ClientSession, sem: asyncio.Semaphore, vuln: str):
        async with sem:
            for attempt in range(self.retry_limit):
                try:
                    async with session.get(f"{self.api_url}/{vuln}", ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            return await response.json()
                        elif response.status == 429:
                            print(f"[{vuln}] Rate limited. Sleeping...")
                            await asyncio.sleep(2 ** attempt + random.random())
                        else:
                            print(f"[{vuln}] Failed with status: {response.status}")
                            return None
                except Exception as e:
                    print(f"[{vuln}] Exception: {e}")
                    await asyncio.sleep(2 ** attempt + random.random())
            print(f"[{vuln}] Failed after {self.retry_limit} retries")
            return None

    # fetches all vuln JSON data for a given list of osv IDs
    async def fetch_all_vulns_json(self, vuln_list):
        results = []
        sem = asyncio.Semaphore(self.max_concurrency)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=200)) as session:
            tasks = [asyncio.create_task(self.fetch(session, sem, vuln)) for vuln in vuln_list]
            responses = await asyncio.gather(*tasks)
            results.extend([res for res in responses if res is not None])
        return results

    # queries the osv API using package name + ecosystem and returns parsed vuln data
    def fetch_osv_data(self, package_name, ecosystem):
        try:
            query = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                }
            }
            response = requests.post("https://api.osv.dev/v1/query", json=query)
            response.raise_for_status()
            vulnerabilities = response.json().get("vulns", [])
            osv_list = []
            for vuln in vulnerabilities:
                osv_id = vuln.get("id")
                summary = vuln.get("summary", "No description available")
                affected = vuln.get("affected", [])
                affected_versions = []
                for affect in affected:
                    affected_versions.extend(affect.get("versions", []))
                osv_list.append({
                    "id": osv_id,
                    "summary": summary,
                    "affected_versions": affected_versions
                })
                print(f"Fetched OSV: {osv_id} - {summary}")
            print(f"Total OSV entries fetched: {len(osv_list)}")
            return osv_list
        except requests.RequestException as e:
            print(f"Error fetching OSV data: {e}")
            return []

    # stores a list of osv items into the Neo4j database
    def store_osv_to_db(self, osv_list):
        for osv in osv_list:
            self.neo4j_manager.upsert_osv(
                osv_id=osv['id'],
                summary=osv['summary'],
                affected_versions=osv['affected_versions']
            )
        self.neo4j_manager.close()


# quick test to run the full flow and time it
if __name__ == "__main__":
    start = time()
    extractor = OSVExtractor()

    #  Get ecosystem folders
    ecosystems = asyncio.run(extractor.fetch_all_ecosystems())

    # Get unique list of vuln IDs
    unique_list = asyncio.run(extractor.get_unique_list(ecosystems))

    # Fetch full JSON for each vuln
    results = asyncio.run(extractor.fetch_all_vulns_json(unique_list))
    end = time()
    print(f"Fetched {len(results)} items in {end - start:.2f} seconds")