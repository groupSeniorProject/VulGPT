import glob
import neo4j
import json
from neo4j import GraphDatabase

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


# Neo4j Log in information, and uri
uri = "neo4j://localhost:7687"
user = "neo4j"
password = "ServerApple12"
# Connects to neo4j
driver = GraphDatabase.driver(uri, auth=(user, password))

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
    
    
