import glob
import json
import os 
import subprocess
import requests
import time
from tqdm import tqdm
from neo4j import GraphDatabase

personal_key = "YOUR_GITHUB_API_KEY_HERE"

headers = {
	'Authorization' : f'token {personal_key}'
}

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

def get_min(tx, query):
	result = tx.run(query)
	out = { }
	for record in result:
		out[record['id']] = record['min']
	return out 

def read_json_file(file_path):
	# Opens json filea nd loads it, and returns.
	with open(file_path, "r", encoding="utf-8") as file:
		return json.load(file)

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

def get_CVE_files():
	data_path = "/mnt/disk-5/osv_data/all_data/*CVE*.json"
	json_data_files = glob.glob(data_path)
	return json_data_files

if __name__ == '__main__':
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
