import json

with open("microservices-demo.json", "r") as f:
    infrastructure = json.load(f)
with open("microservices-pkgs.json", "r") as f:
    packages = json.load(f)
    packages = packages["Results"]

for pod in infrastructure:
    pod_libs = []
    pod_pkgs = next((p for p in packages if pod["label"] in p["Target"]), None)
    if pod_pkgs is not None:
        vulns = pod_pkgs["Vulnerabilities"]
        pod_pkgs = pod_pkgs["Packages"][1:]
        libs = [
            {
                "name": l['Name'],
                "version": l['Version'],
                "artifacts": [],
                "vulnerabilities": [{ "id": v['VulnerabilityID']} for v in vulns if v['PkgName'] == l['Name']]
            }
            for l in pod_pkgs
        ]
        pod["libraries"] = libs

with open("microservices-demo.json", "w") as f:
    infrastructure = json.dump(infrastructure, f, indent=2)