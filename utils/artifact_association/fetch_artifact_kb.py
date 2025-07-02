import requests
import argparse
import json
import os
from tqdm import tqdm

BASE_URL = "https://next.d3fend.mitre.org"

def fetch_artifacts(kb_path):
    """
    Retrieves ID and description for each DAO artifact and builds the knowledge base
    """
    try:
        # Fetch (id, name) of all artifacts
        r = requests.get(BASE_URL+f"/api/dao/artifacts.json")
        r.raise_for_status()
        artifacts = r.json()
        artifacts = artifacts["@graph"]
        artifacts = [ 
            {"id": a["@id"]} 
            for a in artifacts
        ]
        # For each artifact retrieve the associated definition
        s = requests.Session()
        for a in tqdm(artifacts, desc="Fetching artifacts"):
            r = s.get(BASE_URL+f"/api/dao/artifact/{a['id']}.json", timeout=10)
            if r.ok:
                descriptions = r.json()
                descriptions = descriptions["description"]["@graph"]
                for d in descriptions:
                    if d["@id"] == a['id']:
                        if "d3f:definition" in d:
                            a["definition"] = d["d3f:definition"]
                            break
        # Save all in the Knowledge Base
        with open(os.path.join(kb_path, "artifacts.json"), "w") as f:
            json.dump({"artifacts": artifacts}, f, indent=2)
    except requests.exceptions.HTTPError as e:
        print(f"Error while fetching digital artifacts\n: {e}")

def main():
    """
    Simple script to fetch the artifacts and their descriptions
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("out_dir", help="directory in which to save the kb")
    args = parser.parse_args()

    out_path = os.path.join(os.getcwd(), args.out_dir)
    fetch_artifacts(out_path)

if __name__ == "__main__":
    main()