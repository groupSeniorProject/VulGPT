import glob
import neo4j
import json
from neo4j import GraphDatabase
from ortools.sat.python import cp_model
import re

def getOSVFiles():
    # File path for json files to load. 
    data_path = "/mnt/disk-5/osv_data/git_CVE_data/*.json"
    # Creates a list and returns
    json_data_files = glob.glob(data_path)
    return json_data_files

def read_json_file(file_path):
    # Opens json file and loads it, and returns. 
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)
    
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

def simplify_git_name(url):
    if(".com/" in url):
        result =  url.split(".com/")[1].replace("/", " ")
    elif (".org/" in url):
        result = url.split(".org/")[1].replace("/", " ")
    else:
        result = url.strip("/").split("/")[-1]
    return result


def uploadMinimalList(tx, url, minimal_version):
    # Looks for vulnerability with id then adds minimal set version. 
    query =(
        "MATCH (n: GitHub {url: $url}) "
        "SET n.minimal_affected_versions = $minimal_affected_versions"
    )

    # Stores the parameters for the properties
    parameters = {
        'url': url, 
        'minimal_affected_versions' : minimal_version
        
    }

    tx.run(query, parameters)

def stripNonNumbers(version):
    # Gets rid of all non numberic characters
    result = re.sub(r'[^0-9]', '', version)
    if(result == ''):
        return 0
    return float(result)

def getCVEList(tx, url):
    query = ("""
        MATCH (n:GitHub)-[]-(connected)
        WHERE n.url = $url
        RETURN connected.id AS value
    """)
    
    parameters = {'url': url}
    result = tx.run(query, parameters)
    return [record["value"] for record in result]

def getCVEInformation(tx, id):
    query = ("""
               Match (v: Vulnerability) where v.id = $id 
               return v.minimal_affected_versions as value   
        """)
    
    parameters = {'id':id}
    result = tx.run(query, parameters)
    record = result.single()
    return record["value"]

def getParameter(osv ,parameter_name):
    # Tries to get parameter from json file
    try:
        parameter = osv[parameter_name]
        return parameter
    except Exception as message: # Prints error message if it doesnt exist and returns empty
        print(f"Parameter {parameter_name} is empty.")
        return "Empty"

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
        model.Add(sum(version_vars[version] for version in group if version in version_vars) >= 1)

    # Add a contraint that larger the weight the higher the priority
    # The weight is numbers of the version turned into a float. 
    big_weight = 1000
    version_weights = {version: int(stripNonNumbers(version)) for version in versions}

    total_selected = sum(version_vars[version] for version in versions)
    total_version_value = sum(version_vars[version] * version_weights[version] for version in versions)
    model.Minimize(total_selected * big_weight - total_version_value)

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

def checkifNodeExsists(tx, url):
    query = """
            MATCH (g: GitHub {url: $url})
            RETURN g
            """
    parameters = {'url' : url}

    result = tx.run(query, parameters)

    if result.single():
        return True
    return False


# Neo4j Log in information, and uri
uri = "neo4j://localhost:7687"
user = "neo4j"
password = "ServerApple12"
# Connects to neo4j
driver = GraphDatabase.driver(uri, auth=(user, password))

check_connection(driver)
no_solution_error = []

print(f"Getting OSV files...")
json_files = getOSVFiles()
# Prints the number of files to upload
print(f"Number of Files {len(json_files)}")

cve_file = read_json_file(json_files[0])

with driver.session(database='neo4j') as session:
    for url, data in cve_file.items():
        git_name = simplify_git_name(url)

        cve_list = session.execute_write(getCVEList, url)
        #print(cve_list)
        cve_list_of_lists = []
        for cve in cve_list:
            print(f"{cve}: ",end="")
            # Gets the version lists for that cve. 
            file_path = f"/mnt/disk-5/osv_data/all_data/{cve}.json"
            cve_file_json = read_json_file(file_path)
            affected = getParameter(cve_file_json, "affected")

            version_group = []
            for package in affected:
                versions = package["versions"]
                try:
                    # If version is empty then do not add it. 
                    if(versions != []):
                        for version in versions:
                            if version not in version_group:
                                version_group.append(version)
                        # print(f"\nVersion: {version}")
                except Exception as message:
                    print(f"Version list is empty: {message}")
                print(f"Got Version List")

            cve_list_of_lists.append(version_group)
            # Done getting the list of all verisons. 
        cve_minimal_versions = find_minimal_versions(cve_list_of_lists)
        if(cve_minimal_versions == "No solution"):
            no_solution_error.append(git_name)
        print(cve_minimal_versions)
        session.execute_write(uploadMinimalList, url, cve_minimal_versions)
        print(f"Uploaded {git_name}")
print(f"{no_solution_error}")