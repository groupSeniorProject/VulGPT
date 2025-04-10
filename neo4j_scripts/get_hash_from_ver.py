import json
import subprocess
import os
from collections import defaultdict 

EXTENSION_MAP = {
	'.py' : 'Python',
	'.js' : 'JavaScript',
	'.java' : 'Java',
	'.html' : 'HTML',
	'.css' : 'CSS',
	'.md' : 'Markdown',
	'.json' : 'JSON',
	'.yml' : 'YAML',
	'.sh': 'Shell',
	'.go' : 'Go',
	'.rs' : 'Rust',
	'.c' : 'C',
	'.h' : 'C',
	'.cpp' : 'C++',
	'.hpp' : 'C++',
	'.cs' : 'C#',
	'.php' : 'PHP',
	'.rb' : 'Ruby',
	'.swift' : 'Swift',
	'.kt' : 'Kotlin',
	'.ts' : 'TypeScript',
	'.vim' : 'Vim Script',
	'.roff' : 'Roff',
	'.lua' : 'Lua',
	'.m' : 'Matlab', # also for objective-C
	'.asm' : 'Assembly',
	'.l' : 'Lex',
	'.y' : 'Yacc',
	'.smpl' : 'SmPL',
	'awk' : 'Awk',
	'.uscript' : 'UnrealScript',
	'.ps1' : 'PowerShell',
	'.r' : 'R'
	'.pl' : 'Perl'
	'.m4' : 'M4',
	'.sed' : 'SED',
	'.clj' : 'clojure',
	# need to add more file extensions
}

def get_commit_hash_from_tag(repo_url, tag, github_token=None, first=True):
	# since we have to go 2 layers deep into the api we first need to get the tag hash
	# then with the tag has we can get the commit hash 
	if first:
		api_url = f"https://api.github.com/repos/{repo_url.split('/')[-2]}/{repo_url.split('/')[-1]}/git/ref/tags/{tag}"
	else:
		api_url = f"https://api.github.com/repos/{repo_url.split('/')[-2]}/{repo_url.split('/')[-1]}/git/tags/{tag}"

	headers = {}
	if github_token:
		headers['Authorization'] = f'token {github_token}'
	try:
		response = requests.get(api_url, headers=headers)
		response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
		data = response.json()
		if first:
			# this is sha for tag not commit
			return get_commit_hash_from_tag(repo_url, data['object']['sha'], github_token, False)	
		else:
			# this is the commit sha
			return data['object']['sha']
	except requests.exceptions.HTTPError as e:
		if response.status_code == 404:
			print(f"Tag '{tag}' not found in repository. Skipping.")
		elif response.status_code == 403:
			print("api limit reached, try again later")
		elif reponse.status_code == 401:
			print("authorization not successful")
			if github_toke is not None:
				print("trying without token")
				return get_commit_hash_from_tag(repo_url, tag, first=first)
			else:
				print("try using a github token")
		else:
			print(f"HTTP error occurred: {e}")
		return None
	except Exception as e:
		print(f"An error occurred: {e}")
		return None

def shallow_repo(repo_url):
	path = f"/mnt/disk-5/GIT/{repo_url.strip('/').split('/')[-1]}"
	if os.path.exists(path) and os.path.exists(path+"/.git"):
		print(f"Repo already exist at {path}")
	else:
		subprocess.run(["mkdir", path])
		subprocess.run(["git", "-C", path,"-c", "init.defaultbranch=main" ,"init"])
		subprocess.run(["git", "-C", path, "remote", "add", "origin", repo_url+".git"])

def get_working_copy_size(repo_url):
	total_size = 0
	path = f"/mnt/disk-5/GIT/{repo_url.strip('/').split('/')[-1]}"
	for dirpath, dirnames, filenames in os.walk(path):
		if '.git' in dirnames:
			dirnames.remove('.git')  # Skip Git metadata
		for f in filenames:
			fp = os.path.join(dirpath, f)
			total_size += os.path.getsize(fp)
	return total_size

def get_working_copy_lang_breakdown(repo_url):
	repo_path = f"/mnt/disk-5/GIT/{repo_url.strip('/').split('/')[-1]}" 
	# Get file list with extensions
	file_stats = defaultdict(int)
	total_size = 0

	for root, _, files in os.walk(repo_path):
		# Skip hidden directories (including .git)
		if any(dir.startswith('.') for dir in root.split(os.sep)):
			continue
            
		for file in files:
			filepath = os.path.join(root, file)
			try:
				file_size = os.path.getsize(filepath)
				_, ext = os.path.splitext(file)

				# Map extensions to languages
				language = EXTENSION_MAP.get(ext.lower(), "Other")
				file_stats[language] += file_size
				total_size += file_size
			except FileNotFoundError:
				continue

	# Calculate percentages
	return {lang: (size/total_size)*100 for lang, size in file_stats.items()}

def switch_to_commit(repo_url, commit_hash):
	path = f"/mnt/disk-5/GIT/{repo_url.strip('/').split('/')[-1]}"
	subprocess.run(["git", "-C", path, "fetch", "--depth", "1", "origin", commit_hash])
	subprocess.run(["git", "-C", path, "-c", "advice.detachedHead=false", "checkout", "FETCH_HEAD"])
	

# this is an example of how the methods could be used
if __name__ == '__main__':
	repo = "https://github.com/vim/vim"
	ver = "v9.1.0697"
	github_token = None # your git key here as a string 
	commit = get_commit_hash_from_tag(repo_url=repo, tag=ver)
	if commit is not None:
		print(commit)
		shallow_repo(repo)
		switch_to_commit(repo, commit)
		lang = get_working_copy_lang_breakdown(repo)
		print(f"current version size: {round(get_working_copy_size(repo)/1000000, 2)} MB")
		print(f"language breakdown: \n {json.dumps(lang, indent=4)}")
	else:
		print("No Token Found")
