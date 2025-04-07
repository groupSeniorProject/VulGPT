import glob
import json
import re
from tqdm import tqdm
from neo4j import GraphDatabase

# Note: This runs after process_git_cve.py and this cleans up its output file
# giving us the version sotred in neo4j and outputs it into anoter .json file
# so it can be uploaded to neo4j seperately


# Neo4j Log in information, and uri
uri = "neo4j://localhost:7687"
user = "neo4j"
password = "password" #your password here
# Connects to neo4j
driver = GraphDatabase.driver(uri, auth=(user, password))

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

def read_json_file(file_path):
	# Opens json filea nd loads it, and returns.
	with open(file_path, "r", encoding="utf-8") as file:
		return json.load(file)

def write_json_file(file_path, data):
	# writes json files at a specified location
	with open(file_path, 'w') as file:
		json.dump(data, file, indent=4)

def get_query(query):
	with driver.session() as session:
		return session.run(query)

def get_min(tx, query):
	result = tx.run(query)
	out = { }
	for record in result:
		out[record['id']] = record['min']
	return out 

if __name__ == '__main__'
	check_connection(driver)

	query = """
	MATCH (n)
	WHERE n.minimal_affected_versions IS NOT NULL AND n.minimal_affected_versions <> "No solution"
	RETURN n.id AS id, n.minimal_affected_versions AS min
	"""
	with driver.session() as session:
		result = session.execute_read(get_min, query) 

	data = read_json_file("found_data.json")

	new_data = { }
	for url in tqdm(list(data.keys())):
		new_data[url] = { "lang-breakdown" : data[url]['lang-breakdown'], 'size' : data[url]['size']}

		for cve in list(result.keys()):
			if cve in data[url].keys():
				new_data[url][cve] = result[cve]

	write_json_file("found_new_data.json", new_data)
			






