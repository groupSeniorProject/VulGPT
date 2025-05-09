# VulGPT
VulGPT is an LLM-online vulnerability detection tool based on Meta Llama. Web application written in Python 3 and based on Streamlit that uses Neo4j to store Open Source Vulnerabilities (OSV) to query data to generate an analysis using Meta Llama.
## Tabel of contents
• [Usage](#Usage)

• [Setup](#Setup)

## Usage
### Uploading OSV data
setup.py contains uploading OSV to neo4j, getting just CVE files to create a GitHub node, and then to compute and insert the minimal list to neo4j.
```
python3 setup.py
```
### Vulnerability node

Vulnerability node created using OSV.

![image](https://github.com/user-attachments/assets/1a39e195-016b-4035-87b6-88de53d36c66)

### GitHub node

Created using only CVE id's.

![image](https://github.com/user-attachments/assets/b0910925-0e44-458f-a444-647b5ef74f58)

### Uploading minimal list

The minimal list is computed with the setup.py where it would then be merge to its respected CVE id in neo4j.

![image](https://github.com/user-attachments/assets/e3524e57-5710-4c0c-925c-0ebc3ee934d1)

### LLM Analysis
LLM response resulting in three types of classifications -> "Not Promising", "Slightly Promising", and "Very Promising".
```
python3 llm_query.py
```

![image](https://github.com/user-attachments/assets/70075751-8db1-4935-bd88-5ad040821d36)


## Setup
Firstly you will want to install Neo4j into your machine based on your operating system. You'll be able to see the installation process with the following link https://neo4j.com/docs/operations-manual/current/installation/ Note this set up was done in a linux enviroment, although it may be able to set up in other OS enviroments the set up may be different.  
```
sudo systemctl start neo4j
```
Additionally you can make sure neo4j is properly running using the following command. 
```
sudo systemctl status neo4j
```
You are then able to access neo4j through the browser often thorugh the port 7474 or 7687. Once connected you'll see a log in screen that is similar to the following image. The default username and password will be neo4j, afterward it will ask you to change it. 

<img src="read_me_images/neo4j_log_in.png" width="422" height="585">

Once logged in youll be able to see your data once you've uploaded it, which can be done by using the neo4j scripts. You'll first want to download the OSV data which can be downloaded thorugh the follwoing link  https://osv-vulnerabilities.storage.googleapis.com/all.zip or thorugh the following command. Note make sure to unzip the folder. Note: this is the entitery of the OSV data, which is used for the initial set up. It is about of 5 GB at the time of writting. The unzip the zipped folder into a directory of your choice. 
```
wget https://osv-vulnerabilities.storage.googleapis.com/all.zip
unzip all.zip -d /path/to/directory
```
Once installed you are able to run setup.py, Note make sure to add your Neo4j log in information and file path to the dataset folder. Be warned, this can take a while specially when doing GitHub API calls, even longer if you choose not to make an [API token](#getting-github-api-token)

## Streamlit
To view the application running this command allows you to visualize the data which utilizes neo4j queries.
```
streamlit run Home.py
```
### LLM Analysis via Streamlit
![image](https://github.com/user-attachments/assets/3495cc22-766a-4c7a-82d6-f5f9b9c58aa4)

## Auto Update
Installing tmux.
```
sudo apt update
sudo apt install tmux
```
If your wanting run the auto update on the gcp instance tmux can be used. Not only can it used for the scheduler.py but also the streamlit application.
```
tmux new -s auto_update -d 'python3 scheduler.py'
```
Other useful commands to either view the list of current scripts running or to get into that terminal to terminate that script.
```
tmux ls
```
```
tmux attach -t 'auto_update'
```

## LLM Set Up
The main thing you will need to run the llm used in this github is a hugging face account and you will need to request access for the [meta llama 3.1 model collections](https://huggingface.co/collections/meta-llama/llama-31-669fc079a0c406a149a5738f). You will need to create a hugging face token and run the following command while in your python environment 
```
huggingface-cli login
```
after running that command it should ask you to input your hugging face token, after that is complete you are all set up to use the llm

## Getting GitHub API Token
Getting your own github api token is fairly easy, and worth while as the API call rate limits without a key can be very strickt, read more [here](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28#primary-rate-limit-for-unauthenticated-users)

Settings -> Developer Settings -> personal access tokens -> tokens (classis)

for a pure api key you don't need to check any boxes just make the key and insert it into the code. Make sure not to share the key with anyone.
