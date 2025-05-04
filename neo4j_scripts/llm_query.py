import get_hash_from_ver
import json
import gc
import neo4j
import torch
from neo4j import GraphDatabase
from transformers import pipeline, AutoTokenizer

# Neo4j Log in information, and uri
uri = "neo4j://localhost:7687"
user = "neo4j"
password = "password"

def get_cve_information():

    def neo4j_cve_query(tx):
        # This gets a list of vulnaribilities grouped from size of repo, so we start from smallest and build our way up
        query = ("""
        match(n:Vulnerability)-[]-(g:GitHub)
        WHERE g.byte_size <> "None" and g.byte_size > 0
        return n.id as vul_id, n.details as vul_details, g.minimal_affected_versions as versions, g.url as url
        order by g.byte_size asc
        """)

        result = tx.run(query)
        records = list(result)

        return records

    # Connects to neo4j
    driver = GraphDatabase.driver(uri, auth=(user, password))

    with driver.session(database='neo4j') as session:
        data = session.execute_write(neo4j_cve_query)
    return data

def get_github_information(url, versions):
    fhash = None 
    index = -1
    while fhash == None:
        index += 1
        if len(versions) > index:
            fhash = get_hash_from_ver.get_commit_hash_from_tag(url, versions[index], github_token="YOUR_TOKEN_HERE")
        else:
            index -= 1
            break
    code = None
    if fhash != None:
        path = f"/mnt/disk-5/GIT/{url[0].strip('/').split('/')[-1]}"
        get_hash_from_ver.shallow_repo(url)
        switch_pass = get_hash_from_ver.switch_to_commit(path, fhash)
        if switch_pass:
            repo_size = get_hash_from_ver.get_working_copy_size(url)
            if repo_size < 500_000:
                code = get_hash_from_ver.repo_walk(path, url, fhash)
            else:
                print("Repo is to big")
        else:
            print("switch failed")
            
    return versions[index], code


def create_query(vul_id, vul_details, versions, url):
    version, code = get_github_information(url, versions)
    if code != None:
        query = f"""
        Role: You are a security expert who is going to carefuly analyze the following code to asses the likelihood of which files and/or functions introduced the vulnarabilty

        vul_id: {vul_id},
        vul_details: {vul_details}
        github: {url}

        output format:
        """
        
        query += """
        {
            "vulnerabilities": 
                {
                    "headline": "[Vulnerability Headline]",
                    "analysis": "[Detailed analysis of vulnerability]",
                    "cve": "[CVE Identifier]",
                    "most_concerned_functions": ["function1", "function2"],
                    "most_concerned_filenames": ["file1.txt", "file2.c"],
                    "classification": "[Very Promising | Slightly Promising | Not Promising]"
                }
        }
        

        IMPORTANT: it is imperitive that you adhere the output format stated above if not I will PERISH, and that the output is a valid JSON object. It is also VERY important that you do not just simply copy the example 
        """

        query += f"""
        start code base
        ---
        {code}

        response:
        """
    else:
        return None

    return query

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

def llm_response_to_json(response):
    start = response.find('{')
    end = response.rfind('}') + 1
    json_object = json.loads(response[start:end])
    return json_object

def llm_response_pass(headline, analysis, cve, functions, filenames):
    success = True

    if "[Vulnerability Headline]" in headline:
        success = False
    
    if "[Detailed analysis of vulnerability]" in analysis:
        success = False

    if "[CVE Identifier]" in cve:
        success = False

    for function in functions:
        if "function1" in function:
            success = False
        if "function2" in function:
            success = False
    for filename in filenames: 
        if "file1" in filename:
            success = False
        if "file2" in filename:
            success = False
    
    return success

def process_llm_response(cve, response):
    def neo4j_add_llm_response(tx, parameters):
        query = """
        MATCH (n:Vulnerability{id: $cve})
        MERGE (l:llm_response {headline: $headline, analysis: $analysis, functions: $functions, filenames: $filenames, classification: $classification})
        MERGE (l)-[:llm_response_to]->(n)
        """
        

        tx.run(query,parameters)
    try:
        dict = llm_response_to_json(response)
        headline = dict['vulnerabilities']['headline'] 
        analysis = dict['vulnerabilities']['analysis']
        functions = dict['vulnerabilities']['most_concerned_functions']
        filenames = dict['vulnerabilities']['most_concerned_filenames']
        classification = dict['vulnerabilities']['classification']

        if llm_response_pass(headline, analysis, cve, functions, filenames):
            print(f"{dict}\n{headline}\n{cve},\n{functions},\n{filenames},\n{classification}")
            driver = GraphDatabase.driver(uri, auth=(user, password))

            parameters = {
                'cve': cve,
                'headline': headline,
                'analysis': analysis,
                'functions' : functions,
                'filenames' : filenames,
                'classification': classification
            }

            with driver.session(database='neo4j') as session:
                session.execute_write(neo4j_add_llm_response, parameters)
            return True
        else:
            raise ValueError("Response is copied from the prompt") 

    except Exception as e:
        print(f"{e} Error occured, skipping this vulnarability")
        print(response)
        return False

if __name__ == '__main__':
    data = get_cve_information()    
    index = 0
    tries = 0
    MAX_RETRIES = 5
    torch.cuda.empty_cache()
    for record in data:
        success = False
        tries = 0
        if "github.com" in record['url']:
            while success == False and tries < MAX_RETRIES:
                query = create_query(record['vul_id'], record['vul_details'], record['versions'], record['url'])
                #print(query)
                if query != None:
                    if len(query) < 80_000:
                        model_id = "meta-llama/Llama-3.1-8B"
                        pipe = pipeline(
                            "text-generation", 
                            max_new_tokens=500,#This is the amount of tokens the model generates
                            model=model_id, 
                            torch_dtype=torch.bfloat16, 
                            device_map="auto",
                            return_full_text = False
                            )
                        print(len(query))
                        output = pipe(query)
                        success = process_llm_response(record['vul_id'], output[0]['generated_text'])
                        tries += 1
                        # These lines are to help manage memory
                        del pipe
                        gc.collect()
                        torch.cuda.empty_cache()
                    else:
                        print("query too large skip repo")
                        break
                else:
                    print("no code could be found skip")
                    break
            
        if success == False:
            print("could not make a suitable output after 5 tries, skipping repo")

        if index%200 == 0:
            size = get_hash_from_ver.get_dir_size("/mnt/disk-5/GIT")/(1024**3)
            if size > 10:
                get_hash_from_ver.clear_dir("/mnt/disk-5/GIT")	
                print("Clearing GIT")
            else:
                print(f"Current GIT dir size: {size}")
        index += 1