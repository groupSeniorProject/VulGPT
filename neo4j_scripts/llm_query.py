import get_hash_from_ver
import neo4j
import torch
from neo4j import GraphDatabase
import random
from transformers import pipeline

def neo4j_query(tx, name):
    query = ("""
        MATCH (n:GitHub)
        WHERE n.name = $name
        RETURN n.url, n.minimal_affected_versions
    """)
    
    parameters = {'name': name}
    result = tx.run(query, parameters)
    records = list(result)  # Only consume once

    url = [record["n.url"] for record in records]
    version_list = records[0]["n.minimal_affected_versions"] if records else []
    return url, version_list


def get_github_information(gitName):
    # Neo4j Log in information, and uri
    uri = "neo4j://localhost:7687"
    user = "neo4j"
    password = "password"
    # Connects to neo4j
    driver = GraphDatabase.driver(uri, auth=(user, password))

    with driver.session(database='neo4j') as session:
         url, version_list = session.execute_write(neo4j_query, gitName)

    
    print_version_list(version_list)

    while True:
        version = input("Pick a version from list or random for a random version: ")
        if version == "random":
            version = random.choice(version_list)
            break
        elif version in version_list:
            break
        print("Version not in list")
    
    fhash = get_hash_from_ver.get_commit_hash_from_tag(url[0], version, github_token="GIT_HUB_TOKEN HERE")
    code = None 
    if fhash != None:
        path = f"/mnt/disk-5/GIT/{url[0].strip('/').split('/')[-1]}"
        get_hash_from_ver.shallow_repo(url[0])
        switch_pass = get_hash_from_ver.switch_to_commit(path, fhash)
        if switch_pass:
            code = get_hash_from_ver.repo_walk(path, url[0], fhash)
        else:
            print("switch failed")
            
    return url[0], version_list, code
def print_version_list(version_list):
     print("------------------------ Version Lists ------------------------")
     print("| ", end="")
     row_count = 0
     for version in version_list:
        print("{:^24}".format(version), " |", end="")
        row_count += 1
        if row_count == 8:
            print("\n| ", end="")
            row_count = 0

def create_query():
    while True:
            git_name = input("Enter git name: ")
            url, version_list, chunk = get_github_information(git_name)
            break
            print(f"Error Message: {message}")

    with open("cwe_list.txt", "r", encoding="utf-8") as file:
        cwe_list = file.read()

    query = f"""
Identify all the security vulnerabilities in the codebase below.

Your reply must be a valid YAML object equivalent to type LeadList, according to the following Pydantic definitions:
```python
class Lead(BaseModel):
    headline: str = Field(description="a short description of the lead")
    analysis: str = Field(description="in-depth explanation and investigation of the lead. Several sentences at least. Do not include security recommendations: the goal here is to get security researchers started with development of a POC exploit.")
    cwe: str = Field(description="root cause of the vulnerability, as the most specific CWE ID in the list below that applies to the vulnerability. Only include an ID (e.g. CWE-999), not the description of the CWE.")
    function_names: list[str] = Field(description="a list of up to 3 function names where the vulnerability is present. The list may be empty if the vulnerability doesn't map cleanly to specific functions, e.g. some race conditions.")
    filenames: list[str] = Field(description="a list of up to 3 filenames where the vulnerability is present. The list may be empty if the vulnerability doesn't map cleanly to specific files. Filenames must be listed as they are written below, i.e. with their full path relative to the root of the repository.")
    classification: Literal["very promising", "slightly promising", "not promising"]

class LeadList(BaseModel):
    leads: list[Lead]
```

Example YAML output:
```yaml
leads:
- headline: ...
    analysis: |
    ...
    cwe: CWE-...
    function_names:
    - ...
    - ...
    filenames:
    - ...
    - ...
    classification: ...
```

Start your answer with:
```yaml

Below is the CWE list, for your reference. Do NOT copy that list in your response.
<CWE list reference>
{cwe_list}
</CWE list reference>

<><><>codebase<><><>
{chunk}
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
    query = create_query()
    
    model_id = "meta-llama/Llama-3.2-3B"
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    pipe = pipeline(
        "text-generation", 
        model=model_id, 
        torch_dtype=torch.bfloat16, 
        device_map="auto",
        max_new_tokens=5000,  
        tokenizer=tokenizer,
        batch_size=1
        )

    def chunk_code(code_str, max_tokens):
        tokens = tokenizer(code_str, return_tensors='pt')["input_ids"][0]
        chunks = []
        for i in range(0, len(tokens), max_tokens):
            chunk = tokens[i: i+max_tokens]
            chunks.append(tokenizer.decode(chunk))
        return chunks
    
    code_chunks = chunk_code(query, 2040)
    print(type(code_chunks))
    print(len(code_chunks))
    print(pipe(code_chunks))
