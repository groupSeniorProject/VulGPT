# VulGPT
## Setup
Firstly you will want to install Neo4j into your machine based on your operating system. https://neo4j.com/docs/operations-manual/current/installation/
Note for the sake of this set up process, it was done on a linux enviroment. Once installed you are able to start up neo4j with the following command. 
```
sudo systemctl start neo4j
```
Additionally you can make sure neo4j is properly running using the following command. 
```
sudo systemctl status neo4j
```
You are then able to access neo4j through the browser often thorugh the port 7474 or 7687. Once connected you'll see a log in screen that is similar to the following image. The default username and password will be neo4j, afterward it will ask you to change it. 
![Screenhot of Neo4j log in.](read_me_images/neo4j_log_in.png)
Once logged in youll be able to see your data once you've uploaded it, which can be done by using the neo4j scripts. You'll first want to download the OSV data which can be downloaded thorugh the follwoing link  https://osv-vulnerabilities.storage.googleapis.com/all.zip or thorugh the following command. Note make sure to unzip the folder. 
```
wget https://osv-vulnerabilities.storage.googleapis.com/all.zip
```
Once installed you are able to run loadOSVdataset.py, Note make sure to add your Neo4j log in information and file path to the dataset folder. Followed by the process_cve.py script, and upload_git.py. Which will all upload the data to the neo4j. 
