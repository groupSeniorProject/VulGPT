import glob
import neo4j
import json
from neo4j import GraphDatabase

# Neo4j Log in information, and uri
uri = "neo4j://localhost:7687"
user = "neo4j"
password = "neo4j"
# Connects to neo4j
driver = GraphDatabase.driver(uri, auth=(user, password))

def getOSVFiles():
    # File path for json files to load. 
    data_path = "/var/lib/neo4j/import/OSV_sample/OSV_sample/*.json"
    # Creates a list and returns
    json_data_files = glob.glob(data_path)
    return json_data_files

def read_json_file(file_path):
    # Opens json file and loads it, and returns. 
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)
    
def create_vulnerability(tx, vuln_id, summary, details, published, date_modified, affected):
    # Creates properties for the vulnerabilities
    query =(
        "MERGE (v:Vulnerability {id: $vuln_id, summary: $summary, details: $details, "
        "published: $published, date_modified: $date_modified})"
    )

    # Keeps track of ecosystems found in vulnerability
    ecosystem_seen = []
    # Stores the parameters for the properties
    parameters = {
        'vuln_id': vuln_id, 
        'summary': summary,
        'details': details,
        'published': published,
        'date_modified': date_modified
    }
    # idx keeps track the number of ecosystem. 
    idx  = 0
    # For every package found in affected
    for package_info in affected: 
        # If package has no ecosystem prints error message
        try:
            # Gets ecosystem name. 
            ecosystem = package_info['package']['ecosystem']
            print(f"Processing {ecosystem}")

            # If ecosystem has not been processed before
            if ecosystem not in ecosystem_seen:
                # Add ecosystem to list of ecosystems that have been processed
                ecosystem_seen.append(ecosystem)

                # Sanatize ecosystem by getting rid of symbols that messed with cypher syntax
                sanatize_ecosystem = ecosystem.replace(":", "_").replace(".", "_").replace("-", "_").replace(" ","_")

                # Get property name for ecosystem and add it to parameters
                ecosystem_param = f"ecosystem_{sanatize_ecosystem}_{idx}"
                parameters[ecosystem_param] = ecosystem

                # Create query for ecosystem
                query += f"MERGE (e{idx}:Ecosystem {{ecosystem_name: ${ecosystem_param}}})"
                query += f"MERGE (v)-[:IN_ECOSYSTEM]->(e{idx})"
                # Adds one to idx for next ecosystem
                idx = idx + 1
        except Exception as message:
            print(f"Has no package ecosystem: {message}")

    tx.run(query, parameters)


def getParameter(osv ,parameter_name):
    # Tries to get parameter from json file
    try:
        parameter = osv[parameter_name]
        return parameter
    except Exception as message: # Prints error message if it doesnt exist and returns empty
        print(f"Parameter {parameter_name} is empty.")
        return "Empty"

def check_connection(driver):
    try:
        with driver.session() as session:
            result = session.run("RETURN 1 AS connected")
            # If result is returned, connection is successful
            print("Connected to Neo4j:", result.single())
            return True
    except Exception as e:
        # If there is any exception, it indicates a connection failure
        print("Failed to connect to Neo4j:", e)
        return False

# Gets OSV file from desnigated directory, and makes a list
print(f"Getting OSV files...")
json_files = getOSVFiles()
# Prints the number of files to upload
print(f"Number of Files {len(json_files)}")
# Checks that I am connected to neo4j
check_connection(driver)

# During neo4j session
with driver.session(database='neo4j') as session:
    # For every json file in list
    for file in range(len(json_files)):
        # Get the json file information
        osv_data = read_json_file(json_files[file])
        print(f"File Uploading: {osv_data['id']}")
        print("--------------")

        # Checks to see if parameters are in json file. As these parameters are optional. 
        # Id and affected are required. 
        summary = getParameter(osv_data, 'summary')
        details = getParameter(osv_data, 'details')
        published = getParameter(osv_data, 'published')
        modified = getParameter(osv_data, 'modified')

        # Starts a session transaction with function create_vulnerability and parameters
        session.execute_write(create_vulnerability, 
                                  osv_data['id'], 
                                  summary, 
                                  details,
                                  published, 
                                  modified,
                                  osv_data['affected'])
        # Keeps track of file being done. 
        print(f"Done: {file+1}/{len(json_files)}")


