import requests
from vul_auto_update.config.config import CWE_API_URL
from vul_auto_update.database.neo4j_manager import Neo4jManager

class CWEExtractor:
    def __init__(self):
        self.api_url = CWE_API_URL
        self.neo4j_manager = Neo4jManager()

    # latest version
    def get_latest_version(self):
        version_url = f"{self.api_url}/cwe/version"
        try:
            response = requests.get(version_url)
            response.raise_for_status()

            print("Response Content:", response.content.decode('utf-8'))

            version_data = response.json()
            version = version_data.get("ContentVersion")
            print(f"Latest CWE Version: {version}")
            return version

        except requests.RequestException as e:
            print(f"Error fetching CWE version: {e}")
            return None

    # Fetch and parse
    def fetch_cwe_data(self):
        version = self.get_latest_version()
        if not version:
            print("Failed to get CWE version.")
            return []

        cwe_ids = ["79", "89", "200"]

        cwe_list = []
        for cwe_id in cwe_ids:
            cwe_url = f"{self.api_url}/cwe/weakness/{cwe_id}"
            response = requests.get(cwe_url)
            response.raise_for_status()

            # Parse JSON content
            cwe_data = response.json()
            cwe_data_list = cwe_data.get("Weaknesses", [])  # list of weaknesses

            # Loop through the list
            for cwe_data_item in cwe_data_list:
                cwe_id = cwe_data_item.get("ID")
                name = cwe_data_item.get("Name")
                description = cwe_data_item.get("Description", "No description available")

                cwe_list.append({
                    "cwe_id": cwe_id,
                    "name": name,
                    "description": description
                })

                print(f"Fetched CWE: {cwe_id} - {name}")

        print(f"Total CWE entries fetched: {len(cwe_list)}")
        return cwe_list


# test CWEExtractor
if __name__ == "__main__":
    extractor = CWEExtractor()
    cwe_data = extractor.fetch_cwe_data()
    for cwe in cwe_data:
        print(cwe)
