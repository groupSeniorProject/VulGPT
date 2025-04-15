import requests
import asyncio
import aiohttp
import pandas as pd
from time import sleep, time
import random

async def fetch_all_gcs_objects(bucket_url, prefix, headers=None):
    base_url = f"{bucket_url}"
    params = {
        "delimiter": "/",
        "prefix": prefix,
        "fields": "items(kind,mediaLink,metadata,name,size,updated),kind,prefixes,nextPageToken"
    }

    all_items = []
    page = 1

    while True:
        async with aiohttp.ClientSession() as session:
            # print(f"\n--- Page {page} ---")
            response = await session.get(base_url, params=params, headers=headers)
            # response.raise_for_status()
            data = await response.json()

            items = data.get('items', [])
            
            for item in items:
                if item['name'] != 'all.zip':
                    name = item['name']
                    clean_name = name.split('/')[-1].replace('.json', '')
                    all_items.append(clean_name)

            # print(f"Fetched {len(items)} items")

            next_token = data.get('nextPageToken')
            if not next_token:
                break

            params['pageToken'] = next_token
            page += 1

    return all_items

async def fetch_all_ecosystems(bucket_url, headers=None):
    base_url = f"{bucket_url}"
    params = {
        "delimiter": "/",
        "prefix": "",
        "fields": "items(kind,mediaLink,metadata,name,size,updated),kind,prefixes,nextPageToken"
    }

    all_prefixes = []
    page = 1

    while True:
        # print(f"\n--- Page {page} ---")
        async with aiohttp.ClientSession() as session:
            response = await session.get(base_url, params=params, headers=headers, ssl=False)
            # response.raise_for_status()
            data = await response.json()

            prefixes = data.get('prefixes', [])
            # print(f"Fetched {len(prefixes)} prefixes")
            all_prefixes.extend(prefixes)

            next_token = data.get('nextPageToken')
            if not next_token:
                break

            params['pageToken'] = next_token
            page += 1

    return all_prefixes


bucket_url = "https://www.googleapis.com/storage/v1/b/osv-vulnerabilities/o"

start = time()
all_ecosystems = asyncio.run(fetch_all_ecosystems(bucket_url))

def get_unique_list():
    total = 0
    all_objects = {}

    for ecosystem in all_ecosystems:
        clean_name = ecosystem.replace('/', '')

        # ecosystem = "CRAN/"
        all_objects[clean_name] = asyncio.run(fetch_all_gcs_objects(bucket_url, ecosystem))
        print(f"{clean_name}: {len(all_objects[clean_name])}")
        total+=len(all_objects[clean_name])

    combined_list = []

    for value in all_objects.values():
        combined_list.extend(value)

    unique_list = list(set(combined_list))
    return unique_list

unique_list = get_unique_list()

df = pd.DataFrame(unique_list, columns=['Vulnerabilities'])
df.to_csv("tester/vulnerabilities.csv", index=False)

df_csv = pd.read_csv("tester/vulnerabilities.csv")
vulns = df_csv['Vulnerabilities'].to_list()
end = time()
print(f"Fetched {len(vulns)} items in {end - start:.2f} seconds")

url = "https://api.osv.dev/v1/vulns"
print(f"Total OSV {len(vulns)}")

MAX_CONCURRENCY = 50  # Don't overload the server
RETRY_LIMIT = 3

async def fetch(session: aiohttp.ClientSession, sem: asyncio.Semaphore, vuln: str):
    async with sem:
        for attempt in range(RETRY_LIMIT):
            try:
                async with session.get(f"{url}/{vuln}", ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as response:
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
                await asyncio.sleep(2 ** attempt + random.random())  # exponential backoff
        print(f"[{vuln}] Failed after {RETRY_LIMIT} retries")
        return None

async def fetch_all_vulns_json():
    results = []
    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(fetch(session, sem, vuln)) for vuln in vulns]
        responses = await asyncio.gather(*tasks)

        results.extend([res for res in responses if res is not None])
    return results

# Run it
start = time()
results = asyncio.run(fetch_all_vulns_json())
end = time()
print(f"Fetched {len(results)} items in {end - start:.2f} seconds")