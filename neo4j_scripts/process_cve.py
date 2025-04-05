import glob
import json
import requests
import os 
import subprocess

def read_json_file(file_path):
    # Opens json filea nd loads it, and returns.
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)

def write_json_file(file_path, data):
    # writes json files at a specified location
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def get_CVE_files():
    data_path = "/mnt/disk-5/osv_data/all_data/*CVE*.json"
    json_data_files = glob.glob(data_path)
    return json_data_files

cve_files = get_CVE_files()
print(len(cve_files))

# I'm going to use a dictionaries to save the found data since this can easily be converted into a json file
found_data = { }
notFound = 0

# this is used to find the data
for file in range(len(cve_files)):
    try: 
        osv_data = read_json_file(cve_files[file])
        data = { } 
        # from what I've seen the "repo" information is found on the last item in the array, so thats where we are looking at
        for d in osv_data['affected'][len(osv_data['affected']) - 1]['ranges']:
            if d['repo'] not in found_data.keys():
                found_data[d['repo']] = []	
            found_data[d['repo']].append({ osv_data['id'] : d['events']}) 

    except Exception as e:
        print(f"an error has occured: {e}")
        notFound = notFound + 1

# here we can makee the found data into a json file. Possible using this for loading the data without having to run the program again
write_json_file("found_data.json", found_data)
print(notFound)
