import re
import glob
import json
import neo4j
import requests
import time
from tqdm import tqdm
from ortools.sat.python import cp_model
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, GITHUB_TOKEN

driver = neo4j.GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
personal_key = GITHUB_TOKEN

OSV_FILE_PATH = ""
CVE_FILE_PATH = ""

headers = {
	'Authorization' : f'token {personal_key}'
}

def getOSVFiles():
    # File path for json files to load. 
    data_path = OSV_FILE_PATH
    # Creates a list and returns
    json_data_files = glob.glob(data_path)
    return json_data_files

def getCVEdata():
    # File path for json files to load. 

    # From process_git_cve()
    data_path = CVE_FILE_PATH

    # Creates a list and returns
    json_data_files = glob.glob(data_path)
    return json_data_files

def get_CVE_files():
    # Gets all CVE files from directory
    
    # using OSV_FILE_PATH but just the CVE's -> /*CVE*.json 
    data_path = OSV_FILE_PATH
    json_data_files = glob.glob(data_path)
    return json_data_files

def read_json_file(file_path):
    # Opens json file and loads it, and returns. 
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

def insert_osv_to_neo4j():
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
            try:
                session.execute_write(create_vulnerability, 
                                        osv_data['id'], 
                                        summary, 
                                        details,
                                        published, 
                                        modified,
                                        osv_data['affected'])
            except Exception as e:
                continue
            # Keeps track of file being done. 
            print(f"Done: {file+1}/{len(json_files)}")

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
    if result == '':
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

def insert_minimal_list():
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

                # OSV_FILE_PATH with -> /{cve}.json
                file_path = OSV_FILE_PATH
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

def get_min(tx, query):
	result = tx.run(query)
	out = { }
	for record in result:
		out[record['id']] = record['min']
	return out 

def write_json_file(file_path, data):
	# writes json files at a specified location
	with open(file_path, 'w') as file:
		json.dump(data, file, indent=4)

def get_repo_name_from_url(url):
	# Here we are using the url gathered to extract the repo name so we can check if it exist
	return url.strip("/").split("/")[-2:]

def get_repo_size(repo: list):
	if '.git' in repo[1]:
		repo[1] = repo[1][:-4]
	# here we will just get a json file containing a bunch of information about the repo
	api_url = "https://api.github.com/repos/{}/{}".format(repo[0], repo[1])
	response = requests.get(api_url, headers=headers)
	# because of api rate limits will sleep for 1 second 
	time.sleep(1)
	if response.status_code == 200:
		#This is the size given in kB
		size = response.json()['size']
		return size
	# to many request
	elif response.status_code == 429:
		print("(size) I'm going to sleep, see you in an hour") 
		# request is limited by the hour 
		time.sleep(60)
		# try again after an hour
		print("(size) I'm awake now")
		get_repo_languages(repo)
	else:
		print(f"(size) could not get information for repo {repo[0]}/{repo[1]}, code : {response.status_code}")
		return None

def get_lang_sum(data):
	total = 0
	for lang in data.keys():
		total = total + data[lang]
	return total

def get_lang_percent(data, total_sum):
	out = { }
	for lang in data.keys():
		# I'm doing it as 2 seperate statements to hopefully reduce floating point errors
		div = data[lang] / total_sum
		per = round(div * 100, 10)
		out[lang] = per
	return out

def get_repo_languages(repo: list):
	if '.git' in repo[1]:
		repo[1] = repo[1][:-4]
	api_url = "https://api.github.com/repos/{}/{}/languages".format(repo[0], repo[1])
	response = requests.get(api_url, headers=headers)
	# good response
	if response.status_code == 200:
		data = response.json()
		return data
	# to many request
	elif response.status_code == 429 or response.status_code == 403:
		print("(lang) I'm going to sleep, see you in an minute")
		# request is limited by the hour 
		time.sleep(60)
		# try again after an hour
		print("(lang) I'm awake now")
		get_repo_languages(repo)
	else:
		print(f"(lang) could not get information for repo {repo[0]}/{repo[1]}, code : {response.status_code}")
		return None
     
def process_git_cve():
    cve_files = get_CVE_files()

    check_connection(driver)
    query = """
    MATCH (n)
    WHERE n.minimal_affected_versions IS NOT NULL AND n.minimal_affected_versions <> "No solution"
    RETURN n.id AS id, n.minimal_affected_versions AS min
    """
    with driver.session() as session:
        result = session.execute_read(get_min, query) 
    # I'm going to use a dictionaries to save the found data since this can easily be converted into a json file
    found_data = { }
    notFound = 0

    # this is used to find the data
    for file in tqdm(range(len(cve_files))):
        try: 
            osv_data = read_json_file(cve_files[file])
            data = { } 
            # from what I've seen the "repo" information is found on the last item in the array, so thats where we are looking at
            for d in osv_data['affected'][len(osv_data['affected']) - 1]['ranges']:
                if d['repo'] not in found_data.keys():
                    #since this is the first time calculating we will need to add this info
                    lang_data = get_repo_languages(get_repo_name_from_url(d['repo']))
                    if lang_data is None:
                        lang_per = "Could not get"
                    else:
                        lang_per = get_lang_percent(lang_data, get_lang_sum(lang_data))
                    found_data[d['repo']] = {
                            'lang-breakdown' :  lang_per,
                            'size' : get_repo_size(get_repo_name_from_url(d['repo']))
                        } 
                # This will be a default, if something if found it will be replaced in the next for loop
                found_data[d['repo']][osv_data['id']] = "Nothing found" 

                for cve in list(result.keys()):
                    if cve in osv_data['id']:
                        found_data[d['repo']][osv_data['id']] = result[cve]


                    
        except Exception as e:
            if 'repo' not in str(e): 
                print(f"an error occured: {e}")
            notFound = notFound + 1

    # here we can makee the found data into a json file. Possible using this for loading the data without having to run the program again
    write_json_file("found_data.json", found_data)

def getSimpleSize(size):
    units = ["bytes", "KB", "MB", "GB"]

    unit_index = 0
    while size >= 1024 and unit_index < len(units)-1:
        size /= 1024.0
        unit_index += 1 
    
    return f"{size:.2f} {units[unit_index]}"

def createGitNode(tx, git_name, url, byte_size, size, lang_breakdown, data):
    # Creates properties for the vulnerabilities
    query =(
        "MERGE (g:GitHub {name: $git_name, url: $url, byte_size: $byte_size, "
        "size: $size, lang_breakdown: $lang_breakdown})"
    )

    parameters = {
        'git_name': git_name, 
        'url': url,
        'byte_size': byte_size,
        'size': size,
        'lang_breakdown': lang_breakdown
    }    

    tx.run(query, parameters)

    for cve, versions in data.items():
        #print(cve)
        if(cve.startswith("CVE")):
            cve_query = """
            MATCH (v: Vulnerability {id: $cve_id})
            RETURN v
            """

            cve_parameters = {'cve_id': cve}

            result = tx.run(cve_query, cve_parameters)

            if result.single():
                tx.run("""
                MATCH (g:GitHub {url: $url})
                MATCH (v:Vulnerability {id: $cve_id})
                CREATE (v)-[:IN_GITHUB]->(g)
                """, url=url, cve_id=cve)

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

def upload_git():
    check_connection(driver)

    print(f"Getting OSV files...")
    json_files = getOSVFiles()
    # Prints the number of files to upload
    print(f"Number of Files {len(json_files)}")

    cve_file = read_json_file(json_files[0])

    with driver.session(database='neo4j') as session:
        for url, data in cve_file.items():
            git_name = simplify_git_name(url)
            byte_size_of_git = data['size']
            if(byte_size_of_git == None):
                byte_size_of_git = "None"
            lang_breakdown = json.dumps(data['lang-breakdown'])

            try:
                size_of_git = getSimpleSize(int(byte_size_of_git))
            except Exception as message:
                print(f"Size was not integer: {message}")
                size_of_git = "None"

            if(session.execute_write(checkifNodeExsists, url)):
                print(f"Uploaded {git_name}")
                continue

            session.execute_write(createGitNode, 
                                    git_name, 
                                    url, 
                                    byte_size_of_git,
                                    size_of_git, 
                                    lang_breakdown,
                                    data)
            print(f"Uploaded {git_name}")

if __name__ == "__main__":
    # upload all OSV data to neo4j
    insert_osv_to_neo4j()

    # produces -> git_CVE_data
    process_git_cve() 

    # needs git_CVE_data that was created 
    upload_git()

    # insert minimal list to neo4j
    insert_minimal_list()