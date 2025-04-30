import glob
import json
import subprocess
import os
import requests
import shutil
import magic
from tqdm import tqdm
from collections import defaultdict 

# These language extensions where provided by chatgpt, since there are so many and I didn't want to check what the extension is for what. most of them look correct, but there could be some errors
EXTENSION_MAP =  {
    '.c': 'C', '.h': 'C', '.s': 'Assembly',
    '.asm': 'Assembly', '.sh': 'Shell', '.py': 'Python',
    'Makefile': 'Makefile', '.pl': 'Perl', '.rs': 'Rust',
    '.roff': 'Roff', '.cpp': 'C++', '.cc': 'C++',
    '.cxx': 'C++', '.hpp': 'C++', '.hxx': 'C++',
    '.smpl': 'SmPL', '.y': 'Yacc', '.l': 'Lex',
    '.awk': 'Awk', '.jinja': 'Jinja', '.uc': 'UnrealScript',
    '.feature': 'Gherkin', '.ld': 'Linker Script', '.m4': 'M4',
    '.clj': 'Clojure', '.m': 'MATLAB', '.sed': 'sed',
    '.xs': 'XS', '.x': 'RPC', '.m': 'Objective-C',  # Note: .m is also used for MATLAB
    '.cmake': 'CMake', '.java': 'Java', '.d': 'D',
    '.rb': 'Ruby', '.js': 'JavaScript', '.raku': 'Raku',
    '.bat': 'Batchfile', '.ps1': 'PowerShell', '.php': 'PHP',
    '.html': 'HTML', '.cs': 'C#', '.bb': 'BitBake',
    '.star': 'Starlark', '.pas': 'Pascal', '.nasl': 'NASL',
    '.kt': 'Kotlin', '.css': 'CSS', '.swg': 'SWIG',
    '.dcl': 'DIGITAL Command Language', '.pwn': 'Pawn', '.el': 'Emacs Lisp',
    '.plt': 'Gnuplot', '.ll': 'LLVM', '.lua': 'Lua',
    '.vim': 'Vim Script', '.pov': 'POV-Ray SDL', 'Dockerfile': 'Dockerfile',
    '.vbs': 'VBScript', '.mms': 'Module Management System', '.vba': 'VBA',
    '.ec': 'eC', '.r': 'R', '.ts': 'TypeScript',
    '.nsi': 'NSIS', '.xslt': 'XSLT', '.hbs': 'Handlebars',
    '.pgsql': 'PLpgSQL', '.less': 'Less', '.sql': 'SQL',
    '.coffee': 'CoffeeScript', '.go': 'Go', '.scss': 'SCSS',
    '.snip': 'Vim Snippet', '.iss': 'Inno Setup', '.lisp': 'Common Lisp',
    '.plsql': 'PLSQL', '.rtf': 'Rich Text Format', '.mustache': 'Mustache',
    '.gdb': 'GDB', '.ps': 'PostScript', '.gap': 'GAP',
    '.mako': 'Mako', '.thrift': 'Thrift', '.ftl': 'FreeMarker',
    '.sqlpl': 'SQLPL', '.tex': 'TeX', '.groovy': 'Groovy',
    '.rpgle': 'RPGLE', '.icl': 'Clean', '.g4': 'ANTLR',
    '.erl': 'Erlang', '.meson': 'Meson', '.hack': 'Hack',
    '.ml': 'OCaml', '.nix': 'Nix', '.ipynb': 'Jupyter Notebook',
    '.alloy': 'Alloy', '.sml': 'Standard ML', '.dune': 'Dune',
    '.rs': 'RenderScript', '.aj': 'AspectJ', '.tpl': 'Smarty',
    '.vala': 'Vala', '.ex': 'Elixir', '.tla': 'TLA',
    '.mdx': 'MDX', '.njk': 'Nunjucks', '.pegjs': 'PEG.js',
    '.ejs': 'EJS', '.vm': 'Velocity Template Language', '.as': 'ActionScript',
    '.just': 'Just', '.md': 'Markdown', '.scm': 'Scheme',
    '.plg': 'Prolog', '.scala': 'Scala', '.f': 'Fortran',
    '.sci': 'Scilab', '.bsl': '1C Enterprise', '.mm': 'Objective-C++',
    '.fs': 'F#', '.fth': 'Forth', '.nb': 'Mathematica',
    '.ada': 'Ada', '.scd': 'SuperCollider', '.applescript': 'AppleScript',
    '.hx': 'Haxe', '.glsl': 'GLSL', '.cu': 'Cuda',
    '.tcl': 'Tcl', '.pb': 'PureBasic', '.metal': 'Metal',
    '.v': 'Verilog', '.hlsl': 'HLSL', '.csd': 'Csound',
    '.qml': 'QML', '.pro': 'QMake', '.yara': 'YARA',
    '.bib': 'BibTeX Style', '.vb': 'Visual Basic .NET', '.bas': 'Visual Basic 6.0',
    '.fsx': 'F#', '.amp': 'AMPL', '.nss': 'NWScript',
    '.stg': 'StringTemplate', '.sls': 'SaltStack', '.bb': 'BlitzBasic',
    '.soy': 'Closure Templates', '.ftl': 'Fluent', '.twig': 'Twig',
    '.pug': 'Pug', '.vcl': 'VCL', '.svelte': 'Svelte',
    '.ecl': 'ECL', '.sage': 'Sage', '.capnp': "Cap'n Proto",
    '.aug': 'Augeas', '.sass': 'Sass', '.vue': 'Vue',
    '.q': 'q', '.pig': 'PigLatin', '.templ': 'templ',
    '.zig': 'Zig', '.hcl': 'HCL', '.jq': 'jq',
    '.sas': 'SAS', '.mrc': 'mIRC Script', '.ags': 'AGS Script',
    '.praat': 'Praat', '.lsl': 'LSL', '.liquid': 'Liquid',
    '.asp': 'ASP', '.vhdl': 'VHDL', '.ahk': 'AutoHotkey',
    '.styl': 'Stylus', '.mask': 'Mask', '.gcode': 'G-code',
    '.hs': 'Haskell', '.dart': 'Dart', '.elm': 'Elm',
    '.scad': 'OpenSCAD', '.lean': 'Lean', '.io': 'Io',
    '.cfm': 'ColdFusion', '.cob': 'COBOL', '.jsonnet': 'Jsonnet',
    '.cr': 'Crystal', '.qs': 'Q#', '.nf': 'Nextflow',
    '.dsp': 'Faust', '.ipf': 'IGOR Pro', '.do': 'Stata',
    '.asl': 'ASL', '.p6': 'Perl 6', '.robot': 'RobotFramework',
    '.prg': 'xBase', '.motoko': 'Motoko', '.wasm': 'WebAssembly',
    '.p4': 'P4', '.pascal': 'Component Pascal', '.ql': 'CodeQL',
    '.zeek': 'Zeek', '.blade': 'Blade', '.volt': 'Volt',
    '.slim': 'Slim', '.wren': 'Wren', '.rascal': 'Rascal',
    '.clarion': 'Clarion', '.fb': 'FreeBASIC', '.apib': 'API Blueprint',
    '.mod': 'Modula-2', '.dm': 'DM', '.sol': 'Solidity',
    '.ms': 'Groff', '.rexx': 'REXX', '.pike': 'Pike',
    '.boo': 'Boo', '.limbo': 'Limbo', '.idl': 'IDL',
    '.bas': 'BASIC', '.bmx': 'BlitzMax', '.dylan': 'Dylan',
    '.mo': 'Modelica', '.gs': 'Genie', '.qbs': 'QuickBASIC',
    '.j': 'J', '.rkt': 'Racket', '.vhd': 'VHDL',
    '.coq': 'Coq', '.ly': 'LilyPond', '.xq': 'XQuery',
    '.swift': 'Swift', '.jl': 'Julia', '.bf': 'Brainfuck',
    '.e': 'Eiffel', '.nim': 'Nim', '.stan': 'Stan',
    '.idr': 'Idris', '.agda': 'Agda', '.apl': 'APL',
    '.fut': 'Futhark', '.zep': 'Zephir', '.tea': 'Tea',
    '.pony': 'Pony', '.x10': 'X10', '.opa': 'Opa',
    '.astro': 'Astro', '.bal': 'Ballerina', '.xml': 'XML',
    '.proto': 'Protocol Buffer', '.ss': 'Scheme', '.purs': 'PureScript',
    '.mql': 'MQL4', '.mcfunction': 'mcfunction', '.chpl': 'Chapel',
    '.cypher': 'Cypher', '.mojo': 'Mojo', '.golo': 'Golo',
    '.tact': 'Tact', '.ceylon': 'Ceylon', '.carbon': 'Carbon',
    '.smali': 'Smali', '.typ': 'Typst', '.pddl': 'PDDL',
    '.mlir': 'MLIR', '.brs': 'BrighterScript', '.bicep': 'Bicep',
    '.lab': 'LabVIEW', '.smt2': 'SMT', '.bpl': 'Boogie',
    '.fstar': 'F*', '.ck': 'ChucK', '.hy': 'Hy',
    '.pyret': 'Pyret', '.vy': 'Vyper', '.nit': 'Nit',
    '.gleam': 'Gleam', '.fnl': 'Fennel', '.ls': 'LiveScript',
    '.mly': 'OCaml', '.nsh': 'Nushell', '.nu': 'Nu',
    '.imba': 'Imba', '.sql': 'SQL', '.msg': 'OMNeT++ MSG',
    '.spin': 'Propeller Spin', '.nasal': 'Nasal', '.pkl': 'Pkl',
    '.imba': 'Imba',
} 
output_dir = "/mnt/disk-5/all_codes"
# Make sure the output directory exists
os.makedirs(output_dir, exist_ok=True)

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
            if 'commit' in data['object']['url']:
                return data['object']['sha']
            else:
                # this is sha for tag not commit
                return get_commit_hash_from_tag(repo_url, data['object']['sha'], github_token, False)
        else:
            # this is the commit sha
            return data['object']['sha']
    except requests.exceptions.HTTPError as e:
        if response.status_code == 404:
            tqdm.write(f"Tag '{tag}' not found in repository. Skipping.")
        elif response.status_code == 403:
            tqdm.write("api limit reached, try again later")
        elif response.status_code == 401:
            tqdm.write("authorization not successful")
            if github_token is not None:
                tqdm.write("trying without token")
                return get_commit_hash_from_tag(repo_url, tag, first=first)
            else:
                tqdm.write("try using a github token")
        else:
            tqdm.write(f"HTTP error occurred: {e}")
        return None
    except Exception as e:
        tqdm.write(f"An error occurred: {e}")
        return None

def get_dir_size(path):
	total_size = 0
	for dirpath, dirnames, filenames in os.walk(path):
		for f in filenames:
			fp = os.path.join(dirpath, f)
			if os.path.exists(fp):
				total_size += os.path.getsize(fp)
	# returns in bytes
	return total_size	

def shallow_repo(repo_url):
	path = f"/mnt/disk-5/GIT/{repo_url.strip('/').split('/')[-1]}"
	if os.path.exists(path) and os.path.exists(path+"/.git"):
		tqdm.write(f"Repo already exist at {path}")
	else:
		subprocess.run(["mkdir", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		subprocess.run(["git", "-C", path,"-c", "init.defaultbranch=main" ,"init"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		subprocess.run([ "git", "-C", path, "remote", "add", "origin", repo_url+".git"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_working_copy_size(path):
	total_size = 0
	#path = f"/mnt/disk-5/GIT/{repo_url.strip('/').split('/')[-1]}"
	for dirpath, dirnames, filenames in os.walk(path):
		if '.git' in dirnames:
			dirnames.remove('.git')  # Skip Git metadata
		for f in filenames:
			fp = os.path.join(dirpath, f)
			total_size += os.path.getsize(fp)
	return total_size

def get_working_copy_lang_breakdown(repo_path):
	#repo_path = f"/mnt/disk-5/GIT/{repo_url.strip('/').split('/')[-1]}" 
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

def switch_to_commit(path, commit_hash):
	env = os.environ.copy()
	env["GIT_TERMINAL_PROMPT"] = "0"
	output = subprocess.run(["git", "-C", path, "fetch", "--depth", "1", "origin", commit_hash], capture_output=True, text=True, env=env)
	print(output.stderr)
	if "fatal" not in output.stderr:
		subprocess.run(["git", "-C", path, "-c", "advice.detachedHead=false", "checkout", "FETCH_HEAD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
		return True
	else:
		tqdm.write("switch failed")
		return False

def clear_dir(path_to_dir):
	for filename in os.listdir(path_to_dir):
			file_path = os.path.join(path_to_dir, filename)
			try:
				if os.path.isfile(file_path) or os.path.islink(file_path):
					os.remove(file_path)
				elif os.path.isdir(file_path):
					shutil.rmtree(file_path)
			except Exception as e:
				tqdm.write(f'Failed to delete {file_path}. Reason: {e}')
	
def must_include(filename):
	_, ext = os.path.splitext(filename)
	# currently skips md, but this can always be changed
	block_list = ['.css', '.lock', '.md', '.min.js', '.scss', '.txt', '.rst', '.adoc', '.pdf', '.docx', 'pptx', '.xls'
			   , '.csv', '.tsv', '.lock', 'package-lock.json', 'pipfile.lock', '.yarn.lock', 'pnpm-lock.yaml', '.sum', 'go.sum'
			   , '.scss', 'sass', '.less', '.min.js', '.min.css', '.svg', 'png', '.jpg', '.jpeg', 'webp', '.gif']
	# mime_type = magic.from_file(filename, mime=True)
	return ext.lower() in list(EXTENSION_MAP.keys()) and ext.lower() not in block_list

# This function gets, all code from a github repository commit version
def repo_walk(repo_path, repo_url, commit, out=False):
    output = "" 
    output = output + f"repo:{repo_url}\ncommit: {commit}\n"                                             
    for root, dirs, files in os.walk(repo_path):                                                         
        # This will skip all the hidden directories                                                      
        dirs[:] = [d for d in dirs if not d.startswith('.')]                                             
        for file in files:
            if file.startswith('.'):                                                                     
                continue
            if must_include(file):                                                                       
                file_path = os.path.join(root, file)
                file_size = os.path.getsize(file_path)                                                   
                if file_size < 200000:
                    rel_path = os.path.relpath(file_path, repo_path)
                    output = output + f"\n--- {rel_path} ---\n"                                          
                    try:                                                                                 
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as infile:          
                            output = output + infile.read()                                              
                    except Exception as e:                                                               
                        tqdm.write(f"Something went wrong: {e}")
    if out:
        output_file = os.path.join(output_dir, f"{repo_url.strip('/').split('/')[-1]}_{commit}_all_code.txt")
        with open(output_file, 'w', encoding='utf-8') as outfile:                                        
            outfile.write(output)                                                                        
    return output

def full_breakdown(repo, commit):
	path = f"/mnt/disk-5/GIT/{repo.strip('/').split('/')[-1]}"
	#tqdm.write(commit)
	shallow_repo(repo)
	switch_pass = switch_to_commit(path, commit)
	if switch_pass:
		lang = get_working_copy_lang_breakdown(path)
		tqdm.write(f"current version size: {round(get_working_copy_size(repo)/1000000, 2)} MB")
		tqdm.write(f"language breakdown: \n {json.dumps(lang, indent=4)}")
		repo_walk(path, repo, commit)
	else:
		tqdm.write("Skipping file")

# this is an example of how the methods could be used
if __name__ == '__main__':
	def read_json_file(file_path):
		# Opens json filea nd loads it, and returns.
		with open(file_path, "r", encoding="utf-8") as file:
			return json.load(file)
	# This example relies on having the data chunks from https://github.com/timothee-chauvin/eyeballvul_experiments
	path_to_jsons = "/path/to/eyeballvul_experiments/data/chunks/*.json"
	json_data_files = glob.glob(path_to_jsons)
	pbar = tqdm(range(len(json_data_files)))
	for file in pbar:
		data = read_json_file(json_data_files[file])		
		try:
			pbar.set_description(f"working on {data['repo_url'].strip('https://github.com/')}")
			full_breakdown(data['repo_url'], data['commit'])
			# since checking the size of the dir can be quite an intensive process, we will only do it every 200 file process
			if file % 200 == 0:
				#if we have more than 10GB worth of repos in our git folder clear folder and keep going
				# this is to help manage space
				size = get_dir_size("/mnt/disk-5/GIT")/(1024**3)
				if size > 10:
					clear_dir("/mnt/disk-5/GIT")	
					tqdm.write("Clearing GIT")
				else:
					tqdm.write(f"Current GIT dir size: {size}")
		except Exception as e:
			tqdm.write(f"something went wrong with {json_data_files[file]}: {e}")
