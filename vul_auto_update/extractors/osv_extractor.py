import requests
from vul_auto_update.database.neo4j_manager import Neo4jManager

class OSVExtractor:
    def __init__(self):
        self.api_url = "https://api.osv.dev/v1/query"
        self.neo4j_manager = Neo4jManager()

    def fetch_and_store_osv(self, package_name, ecosystem):
        osv_list = self.fetch_osv_data(package_name, ecosystem)
        for osv in osv_list:
            self.neo4j_manager.upsert_osv(
                osv_id=osv['id'],
                summary=osv['summary'],
                affected_versions=osv['affected_versions']
            )
        self.neo4j_manager.close()

    # package name and ecosystem
    def fetch_osv_data(self, package_name, ecosystem):
        try:
            query = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                }
            }
            response = requests.post(self.api_url, json=query)
            response.raise_for_status()

            # parse JSON
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

# test OSVExtractor
if __name__ == "__main__":
    extractor = OSVExtractor()
    package_name = "flask"
    ecosystem = "PyPI"
    osv_data = extractor.fetch_osv_data(package_name, ecosystem)
    for osv in osv_data:
        print(osv)