import os
import argparse
import requests
import json
from tqdm import tqdm

BASE_URL = "https://next.d3fend.mitre.org"

def fetch_attack_techniques(kb_path):
    """
    Retrieves information for about all ATT&CK Techniques
    """
    try:
        # Get the version of the D3FEND Ontology
        r = requests.get(BASE_URL+"/api/version.json")
        r.raise_for_status()
        version = r.json()
        version = version["version"]
        # If the ATT&CK techniques are already present and up to date do not continue
        if os.path.isfile(os.path.join(kb_path, "attack-techniques.json")):
            with open(os.path.join(kb_path, "attack-techniques.json")) as f:
                if json.load(f)["version"] == version:
                    print("ATT&CK Techniques already up to date.")
                    return
        # Fetch (id, name, definition) of all techniques
        r = requests.get(BASE_URL+"/api/offensive-technique/all.json")
        r.raise_for_status()
        off_techniques = r.json()
        off_techniques = off_techniques["@graph"]
        off_techniques = [ 
            {"id": t["d3f:attack-id"], 
            "name": t["rdfs:label"], 
            "definition": t["d3f:definition"]} 
            for t in off_techniques
        ]
        # For each ATT&CK Technique retrieve the D3FEND Techniques that counter it
        s = requests.Session()
        for t in tqdm(off_techniques, desc="Fetching techniques"):
            r = s.get(BASE_URL+f"/api/offensive-technique/attack/{t['id']}.json", timeout=10)
            if r.ok:
                def_techniques = set()
                bindings = r.json()
                bindings = bindings["off_to_def"]["results"]["bindings"]
                for b in bindings:
                    if "def_tech_id" in b and b["def_tech_id"]["type"] == "literal":
                        def_techniques.add(b["def_tech_id"]["value"])
                t["countermeasures"] = list(def_techniques)
            else:
                t["countermeasures"] = []
        # Save all in the Knowledge Base
        with open(os.path.join(kb_path, "attack-techniques.json"), "w") as f:
            json.dump({"version": version, "techniques": off_techniques}, f, indent=2)
    except requests.exceptions.HTTPError as e:
        print(f"Error while fetching ATT&CK techniques\n: {e}")


def fetch_defend_techniques(kb_path):
    """
    Retrieves information for about all ATT&CK Techniques
    """
    try:
        # Get the version of the D3FEND Ontology
        r = requests.get(BASE_URL+"/api/version.json")
        r.raise_for_status()
        version = r.json()
        version = version["version"]
        # If the D3FEND techniques are already present and up to date do not continue
        if os.path.isfile(os.path.join(kb_path, "defend-techniques.json")):
            with open(os.path.join(kb_path, "defend-techniques.json")) as f:
                if json.load(f)["version"] == version:
                    print("D3FEND Techniques already up to date.")
                    return
        # Fetch (id, name) of all techniques
        r = requests.get(BASE_URL+f"/api/technique/all.json")
        r.raise_for_status()
        def_techniques = r.json()
        def_techniques = def_techniques["@graph"]
        def_techniques = [ 
            {"id": t["d3f:d3fend-id"], 
            "name": t["rdfs:label"]} 
            for t in def_techniques
        ]
        # Save all in the Knowledge Base
        with open(os.path.join(kb_path, "defend-techniques.json"), "w") as f:
            json.dump({"version": version, "techniques": def_techniques}, f, indent=2)
    except requests.exceptions.HTTPError as e:
        print(f"Error while fetching D3FEND techniques:\n {e}")


def fetch_artifacts(kb_path):
    """
    Retrieves information for about all DAO Artifacts
    """
    try:
        # Get the version of the D3FEND Ontology
        r = requests.get(BASE_URL+"/api/version.json")
        r.raise_for_status()
        version = r.json()
        version = version["version"]
        # If the artifacts are already present and up to date do not continue
        if os.path.isfile(os.path.join(kb_path, "artifacts.json")):
            with open(os.path.join(kb_path, "artifacts.json")) as f:
                if json.load(f)["version"] == version:
                    print("Artifacts already up to date.")
                    return
        # Fetch (id, name) of all artifacts
        r = requests.get(BASE_URL+f"/api/dao/artifacts.json")
        r.raise_for_status()
        artifacts = r.json()
        artifacts = artifacts["@graph"]
        artifacts = [ 
            {"id": a["@id"], 
            "name": a["rdfs:label"]} 
            for a in artifacts
        ]
        # For each artifact retrieve the associated ATT&CK and D3FEND Techniques
        s = requests.Session()
        for a in tqdm(artifacts, desc="Fetching artifacts"):
            r = s.get(BASE_URL+f"/api/dao/artifact/{a['id']}.json", timeout=10)
            if r.ok:
                bindings = r.json()
                off_techniques = set()
                off_bindings = bindings["da_to_off"]["results"]["bindings"]
                for b in off_bindings:
                    if "off_tech_id" in b and b["off_tech_id"]["type"] == "literal":
                        off_techniques.add(b["off_tech_id"]["value"])
                a["da_to_off"] = list(off_techniques)
                def_techniques = set()
                def_bindings = bindings["da_to_def"]["results"]["bindings"]
                for b in def_bindings:
                    if "def_tech_label" in b and b["def_tech_label"]["type"] == "literal":
                        def_techniques.add(b["def_tech_label"]["value"])
                a["da_to_def"] = list(def_techniques)
            else:
                a["da_to_off"] = []
                a["da_to_def"] = []
        # Save all in the Knowledge Base
        with open(os.path.join(kb_path, "artifacts.json"), "w") as f:
            json.dump({"version": version, "artifacts": artifacts}, f, indent=2)
    except requests.exceptions.HTTPError as e:
        print(f"Error while fetching digital artifacts\n: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("out_dir", help="path to the directory in which to output the kb")
    parser.add_argument("-a", "--attack", action="store_true", help="retrieve ATT&CK techniques info")
    parser.add_argument("-d", "--defend", action="store_true", help="retrieve D3FEND techniques info")
    parser.add_argument("-r", "--artifacts", action="store_true", help="retrieve DAO artifacts info")
    args = parser.parse_args()

    full = not args.attack and not args.defend and not args.artifacts
    kb_path = os.path.join(os.getcwd(), args.out_dir, "kb")
    if args.attack or full:
        os.makedirs(kb_path, exist_ok=True)
        fetch_attack_techniques(kb_path)
    if args.defend or full:
        os.makedirs(kb_path, exist_ok=True)
        fetch_defend_techniques(kb_path)
    if args.artifacts or full:
        os.makedirs(kb_path, exist_ok=True)
        fetch_artifacts(kb_path)

    
if __name__ == "__main__":
    main()