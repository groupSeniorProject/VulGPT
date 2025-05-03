import get_hash_from_ver
import neo4j
import torch
from neo4j import GraphDatabase
from transformers import pipeline, AutoTokenizer

def get_cve_information():

    def neo4j_cve_query(tx):
        # This gets a list of vulnaribilities grouped from size of repo, so we start from smallest and build our way up
        query = ("""
        match(n:Vulnerability)-[]-(g:GitHub)
        WHERE g.byte_size <> "None" and g.byte_size > 0
        return n.id as vul_id, n.details as vul_details, n.minimal_affected_versions as versions, g.url as url
        order by g.byte_size asc
        """)

        result = tx.run(query)
        records = list(result)

        return records

    # Neo4j Log in information, and uri
    uri = "neo4j://localhost:7687"
    user = "neo4j"
    password = "password"
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
            fhash = get_hash_from_ver.get_commit_hash_from_tag(url, versions[index], github_token="YOUR_API_KEY_HERE")
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
    

    IMPORTANT: it is imperitive that you adhere the output format stated above if not I will PERISH, and that the output is a valid JSON object 
    """

    query += f"""
    start code base
    ---
    {code}

    response:
    """

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

if __name__ == '__main__':
    data = get_cve_information()    
    index = 0
    torch.cuda.empty_cache()
    query = create_query(data[174]['vul_id'], data[174]['vul_details'], data[174]['versions'], data[174]['url'])
    #print(query)

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
    start = output[0]['generated_text'].find('{')
    end = output[0]['generated_text'].rfind('}') + 1
    print(output[0]['generated_text'][start:end])