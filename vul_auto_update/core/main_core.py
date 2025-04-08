import argparse
from vul_auto_update.extractors.cwe_extractor import CWEExtractor
from vul_auto_update.extractors.osv_extractor import OSVExtractor
from vul_auto_update.updaters.auto_updater import AutoUpdater
from vul_auto_update.database.neo4j_manager import Neo4jManager

def extract_cwe():
    print("[INFO] Extracting CWE Data...")
    extractor = CWEExtractor()
    cwe_data = extractor.fetch_cwe_data()
    for cwe in cwe_data:
        print(cwe)

def extract_osv(package_name, ecosystem):
    print(f"[INFO] Extracting OSV Data for {package_name} in {ecosystem}...")
    extractor = OSVExtractor()
    osv_data = extractor.fetch_osv_data(package_name, ecosystem)
    for osv in osv_data:
        print(osv)

def start_auto_update():
    print("[INFO] Starting Auto Update...")
    updater = AutoUpdater()
    updater.run()

def view_cwe():
    print("[INFO] Viewing all CWE Nodes...")
    db_manager = Neo4jManager()
    db_manager.view_cwe()

def view_osv():
    print("[INFO] Viewing all OSV Nodes...")
    db_manager = Neo4jManager()
    db_manager.view_osv()

def delete_cwe(cwe_id):
    print(f"[INFO] Deleting CWE Node with ID: {cwe_id}...")
    db_manager = Neo4jManager()
    db_manager.delete_cwe(cwe_id)

def delete_osv(osv_id):
    print(f"[INFO] Deleting OSV Node with ID: {osv_id}...")
    db_manager = Neo4jManager()
    db_manager.delete_osv(osv_id)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vul Auto Update Core CLI")
    parser.add_argument("--extract_cwe", action="store_true", help="Extract CWE data")
    parser.add_argument("--extract_osv", nargs=2, metavar=("PACKAGE", "ECOSYSTEM"), help="Extract OSV data")
    parser.add_argument("--auto_update", action="store_true", help="Start auto update")
    parser.add_argument("--view_cwe", action="store_true", help="View all CWE nodes")
    parser.add_argument("--view_osv", action="store_true", help="View all OSV nodes")
    parser.add_argument("--delete_cwe", metavar="CWE_ID", help="Delete a CWE node by ID")
    parser.add_argument("--delete_osv", metavar="OSV_ID", help="Delete an OSV node by ID")

    args = parser.parse_args()

    if args.extract_cwe:
        extract_cwe()
    elif args.extract_osv:
        extract_osv(args.extract_osv[0], args.extract_osv[1])
    elif args.auto_update:
        start_auto_update()
    elif args.view_cwe:
        view_cwe()
    elif args.view_osv:
        view_osv()
    elif args.delete_cwe:
        delete_cwe(args.delete_cwe)
    elif args.delete_osv:
        delete_osv(args.delete_osv)
    else:
        print("No valid arguments provided. Use --help for options.")
