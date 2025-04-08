from datetime import datetime
from vul_auto_update.extractors.cwe_extractor import CWEExtractor
from vul_auto_update.extractors.osv_extractor import OSVExtractor

class AutoUpdater:
    def __init__(self):
        self.cwe_extractor = CWEExtractor()
        self.osv_extractor = OSVExtractor()

    def update_cwe(self):
        print("\n[INFO] Updating CWE Data...")
        cwe_list = self.cwe_extractor.fetch_cwe_data()
        print(f"[INFO] Fetched {len(cwe_list)} CWE entries.")
        for cwe in cwe_list:
            print(f"[INFO] Storing CWE: {cwe['cwe_id']} - {cwe['name']}")
            self.cwe_extractor.neo4j_manager.upsert_cwe(
                cwe_id=cwe['cwe_id'],
                name=cwe['name'],
                description=cwe['description']
            )
        self.cwe_extractor.neo4j_manager.close()

    def update_osv(self):
        print("\n[INFO] Updating OSV Data...")
        package_name = "flask"
        ecosystem = "PyPI"
        osv_list = self.osv_extractor.fetch_osv_data(package_name, ecosystem)
        print(f"[INFO] Fetched {len(osv_list)} OSV entries.")
        for osv in osv_list:
            print(f"[INFO] Storing OSV: {osv['id']} - {osv['summary']}")
            self.osv_extractor.neo4j_manager.upsert_osv(
                osv_id=osv['id'],
                summary=osv['summary'],
                affected_versions=osv['affected_versions']
            )
        self.osv_extractor.neo4j_manager.close()

    def run(self):
        print("\n[INFO] Starting Auto Update...")
        print(f"[INFO] Update started at: {datetime.now()}")
        self.update_cwe()
        self.update_osv()
        print(f"[INFO] Update completed at: {datetime.now()}")

if __name__ == "__main__":
    updater = AutoUpdater()
    updater.run()
