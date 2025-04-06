import glob
import json
import re
from ortools.sat.python import cp_model
from neo4j import GraphDatabase

# Neo4j Log in information, and uri
uri = "neo4j://localhost:7687"
user = "neo4j"
password = "ServerApple12"
# Connects to neo4j
driver = GraphDatabase.driver(uri, auth=(user, password))


def get_CVE_files():
    # Gets all CVE files from directory
    data_path = "/mnt/disk-5/osv_data/all_data/*CVE*.json"
    json_data_files = glob.glob(data_path)
    return json_data_files

def read_json_file(file_path):
    # Opens and reads json file
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)

def getParameter(osv ,parameter_name):
    # Tries to get parameter from json file
    try:
        parameter = osv[parameter_name]
        return parameter
    except Exception as message: # Prints error message if it doesnt exist and returns empty
        print(f"Parameter {parameter_name} is empty.")
        return "Empty"
    
def stripNonNumbers(version):
    # Gets rid of all non numberic characters
    result = re.sub(r'[^0-9]', '', version)
    if(result == ''):
        return 0
    return float(result)
    
def find_minimal_versions(version_groups):
    # Create Google Sp Solver
    model = cp_model.CpModel()

    # Makes the list of list version into one, and gets rid of any duplicates. 
    versions = set([version for group in version_groups for version in group])
    # Sorts them just in case they are not sorted. 
    versions = sorted(versions, reverse=True)

    # Create a variable to add a weight for the Solver to use for decisions. 
    version_vars = {version: model.NewBoolVar(version) for version in versions}

    # Add a contraint to the solver that one version must be chosen for every version list
    for group in version_groups:
        model.Add(sum(version_vars[version] for version in group if version in version_vars) == 1)

    # Add a contraint that larger the weight the higher the priority
    # The weight is numbers of the version turned into a float. 
    model.Maximize(sum(version_vars[version] * stripNonNumbers(version) for version in versions))

    # Step 4: Objective function: minimize the number of selected versions


    # Solve the model and check status
    solver = cp_model.CpSolver()
    status = solver.Solve(model)

    # Ensure that the model solution is optimal and meets the contraints. 
    if status == cp_model.OPTIMAL or status == cp_model.FEASIBLE:
        selected_versions = [version for version in versions if solver.Value(version_vars[version]) == 1]
        return selected_versions
    # If it does not meet the constraints then there is no solution. 
    else:
        return "No solution"

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
    
def add_minimal_list(tx, vuln_id, minimal_version):
    # Looks for vulnerability with id then adds minimal set version. 
    query =(
        "MATCH (v:Vulnerability {id: $vuln_id}) "
        "SET v.minimal_affected_versions = $minimal_affected_versions"
    )

    # Stores the parameters for the properties
    parameters = {
        'vuln_id': vuln_id, 
        'minimal_affected_versions' : minimal_version
        
    }

    tx.run(query, parameters)

# Gets CVE files and prints the number of them
cve_files = get_CVE_files()
print(len(cve_files))

check_connection(driver)

# Adds any vulnerablity that did not have a solution
no_solution = open("no_solution.txt", 'a')

with driver.session(database='neo4j') as session:
    # For every json file in list
    for file in range(len(cve_files)):
        # Get the json file information
        osv_data = read_json_file(cve_files[file])
        print(f"File Uploading: {osv_data['id']}")
        print("--------------")

        # Checks to see if parameters are in json file. As these parameters are optional. 
        # Id and affected are required. 

        # gets affected from json file
        affected = getParameter(osv_data, 'affected')
        version_group = []
        # Goes through every package in affected and gets the version
        for package in affected:
            version = package["versions"]
            try:
                # If version is empty then do not add it. 
                if(version != []):
                    version_group.append(version)
                    # print(f"\nVersion: {version}")
            except Exception as message:
                print(f"Version list is empty: {message}")
        #print(f"Version Group: {version_group}")
        # If the group of versions are empty then skip CVE file
        if version_group == []:
            continue
        
        # Find the minimal list
        minimal_list = find_minimal_versions(version_group)
        # If no solution was found add id to text file for further analysis
        if(minimal_list == "No solution"):
            no_solution.write(f"{osv_data['id']},")
        print(minimal_list)

         # Starts a session transaction with function add minimal list
        session.execute_write(add_minimal_list, 
                                  osv_data['id'], 
                                  minimal_list)
        # Keeps track of file being done. 
        print(f"Done: {file+1}/{len(cve_files)}")
no_solution.close()
driver.close()