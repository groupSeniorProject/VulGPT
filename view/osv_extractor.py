import asyncio
import aiohttp
import random
from time import time
from neo4j_manager import Neo4jManager

class OSVExtractor:
    def __init__(self):
        self.api_url = "https://api.osv.dev/v1/vulns"
        self.bucket_url = "https://www.googleapis.com/storage/v1/b/osv-vulnerabilities/o"
        self.neo4j_manager = Neo4jManager()
        self.max_concurrency = 250
        self.retry_limit = 3

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
    
    # returns a list of all osv ids from a specific ecosystem folder
    async def fetch_all_gcs_objects(self, bucket_url, prefix, headers=None):
        params = {
            "delimiter": "/",
            "prefix": prefix,
            "fields": "items(kind,mediaLink,metadata,name,size,updated),kind,prefixes,nextPageToken"
        }

        all_items = []
        async with aiohttp.ClientSession() as session:
            while True:
                async with session.get(bucket_url, params=params, headers=headers) as response:
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

    # takes in list of ecosystems, returns a unique list of all osv IDs
    async def get_unique_list(self, all_ecosystems, headers=None):
        total = 0
        all_objects = {}

        tasks = []
        for ecosystem in all_ecosystems:
            tasks.append(asyncio.create_task(self.fetch_all_gcs_objects(self.bucket_url, ecosystem, headers)))
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
                            data = await response.json()
                            return {
                                'id': data['id'], 
                                'summary': data.get('summary', "Empty"),
                                'details': data.get('details', "Empty"),
                                'published': data.get('published', "Empty"),
                                'modified': data.get('modified', "Empty"),
                                'affected': [
                                    {
                                        'package': {
                                            'name': aff.get('package', {}).get('name', 'Empty'),
                                            'ecosystem': aff.get('package', {}).get('ecosystem', 'Empty')
                                        },
                                        'versions': aff.get('versions', [])
                                    }
                                    for aff in data.get('affected', [])
                                    if 'package' in aff
                                ]
                            }
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
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=self.max_concurrency)) as session:
            tasks = [asyncio.create_task(self.fetch(session, sem, vuln)) for vuln in vuln_list]
            responses = await asyncio.gather(*tasks)
            results.extend([res for res in responses if res is not None])
        return results

    # main function
    async def main(self):
        neo4j = self.neo4j_manager
        start = time()
        ecosystems = await self.fetch_all_ecosystems()
        unique_list = await self.get_unique_list(ecosystems)
        await neo4j.create_constraint()
        vulnerabilities = await self.fetch_all_vulns_json(unique_list)
        await neo4j.insert_all_vulnerabilities(vulnerabilities)
        end = time()
        print(f"Fetched {len(vulnerabilities)} items in {end - start:.2f} seconds")
        await neo4j.close()