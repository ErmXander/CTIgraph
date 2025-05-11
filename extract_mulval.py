import json
import traceback
import os
import argparse
import shutil
import stix2
import subprocess

from kb.artifacts import artifacts, artifacts_to_technique as a2t, artifacts_to_countermeasure as a2c
from kb.techniques import techniques, technique_postconditions as t_post, technique_preconditions as t_pre



def parse_cti(bundle_path):
    '''
    Parse a STIX2.x bundle looking for attack-pattern objects that represent a MITRE ATT&CK Technique and any 
    vulnerability object with related to them.

    args:
        bundle_path: path to the STIX2.x bundle
    returns:
        list of parsed ATT&CK Techniques in the form:
        [{'id': tid, 
        'name': technique_name
        'vulns': [cve_id1, cve_id2, ...]}, ...]
    '''
    techniques = []
    try:
        with open(bundle_path, "r") as f:
            bundle = json.load(f)
        bundle = stix2.parse(bundle)
        attack_patterns = [o for o in bundle.objects if isinstance(o, stix2.AttackPattern)]
        relationships = [o for o in bundle.objects if isinstance(o, stix2.Relationship)]
        vulnerabilities = [o for o in bundle.objects if isinstance(o, stix2.Vulnerability)]
        for ap in attack_patterns:
            t = {}
            references = ap["external_references"]
            # find the External Reference linked to ATT&CK
            for r in references:
                if r["source_name"] == "mitre-attack":
                    t["id"] = r["external_id"]
                    break
            # if no reference is to ATT&CK ignore the attack-pattern
            if "id" not in t:
                continue
            t["name"] = ap["name"]
            # find the vulnerabilities target by the attack-pattern
            related_objs = [r["target_ref"] for r in relationships if r["source_ref"]==ap["id"]]
            vulns = [v["name"] for v in vulnerabilities if v["id"] in related_objs]
            if vulns:
                t["vulns"] = vulns
            techniques.append(t)   
    except Exception as e:
        print(f"Error during CTI parsing: {e}")
        return []
    
    return techniques


def extract_technique_inputs(technique_list):
    '''
    Extract MulVAL facts and rules from a a list of techniques with their exploited vulnerabilities.
    A fact is extracted for each artifact of the technique (techniqueArtifact(tid, artid)) and each exploited
    vulnerability (techniqueExploits(tid, vulid)).
    A rule is created for each technique (tid_attack_step(Pod)) representing the execution of a specific
    technqiue on a pod; the rule is tabled and initialized.
    The rule is satisfied if the pod and technique have compatible artifacts (podTargetable(Pod, TID))
    or in addition, if the technique targets one or more vulnerabilities, if the pod has one of the exploited
    vulnerabilities (podExploitable(Pod, TID)); in addition other predicates are added to the rule based on the
    technique preconditions.
    For each of the technique postconditions a rule is created representing that the execution of a technique on
    a pod causes a specific consequence.
    Attack goals are extracted from the possible ways in which pods could be compromised given the techiques'
    postconditions.

    args:
        technique_list: list of techniques in the form:
        [{'id': tid, 
        'name': technique_name
        'vulns': [cve_id1, cve_id2, ...]}, ...]
    returns:
        technique_facts: MulVAL facts extracted from the techniques
        technique_rules: MulVAL rules extracted from the techniques
        goals: MulVAL facts representing the possible goals for the given set of techniques
    '''
    technique_facts = []
    technique_rules = []
    goals = set()
    for t in technique_list:
        # if the technique is not in the kb skip it
        if t["id"] not in [technique["id"] for technique in techniques]:
            continue

        # table the derived technique rule
        technique_rules.append(f"derived({t['id']}_attack_step(_pod)).")
        technique_rules.append(f":- table {t['id']}_attack_step/1.")

        rule = f"interaction_rule(\n\t({t['id']}_attack_step(Pod) :-"
        for artid, tids in a2t.items():
            if t["id"] in tids:
                # extract technique artifacts
                technique_facts.append(f"techniqueArtifact({t['id']}, {artid}).")
        if "vulns" in t:
            for v in t["vulns"]:
                # extract techique exploited vulnerabilities
                technique_facts.append(f"techniqueExploits({t['id']}, {v}).")
            if t["vulns"]:
                rule += f"\n\t\tpodExploitable(Pod, {t['id']})"  # add condition on artifacts+vulns if vulns present
            else: 
                rule += f"\n\t\tpodTargetable(Pod, {t['id']})"
        else:
            rule += f"\n\t\tpodTargetable(Pod, {t['id']})"  # else consider only artifacts
        # extract the various preconditions
        for pre in t_pre[t["id"]]:
            if pre["type"] == "reachable":
                port = "_" if "port" not in pre or pre["port"] == "*" else pre["port"]
                proto = "_" if "proto" not in pre or pre["proto"] == "*" else pre["proto"].lower()
                rule += f",\n\t\treachable(Pod, {proto}, {port})"
            if pre["type"] == "codeExec":
                rule += f",\n\t\tcodeExec(Pod)"
            if pre["type"] == "fileAccess":
                perm = "_" if "perm" not in pre or pre["perm"] == "*" else pre["perm"].lower()
                file = "_" if "file" not in pre or pre["file"] == "*" else f'\"{pre["file"].lower()}\"'
                rule += f",\n\t\tfileAccess(Pod, {file}, {perm})"
            if pre["type"] == "privilege":
                level = "_" if "level" not in pre or pre["level"] == "*" else pre["level"].lower()
                rule += f",\n\t\tprivilege(Pod, {level})"
            if pre["type"] == "credentialAccess":
                account = "_" if "account" not in pre or pre["account"] == "*" else pre["account"].lower()
                rule += f",\n\t\tcredentialAccess({account})"
            if pre["type"] == "misconfiguration":
                rule += f",\n\t\tmisconfiguration(Pod, {pre['kind']})"
            if pre["type"] == "mounts":
                kind = "_" if "kind" not in pre or pre["kind"] == "*" else pre["kind"].lower()
                path = "_" if "path" not in pre or pre["path"] == "*" else f"\"{pre['path'].lower()}\""
                rule += f",\n\t\tmounts(Pod, {kind}, {path})"
            if pre["type"] == "imageTrustLevel":
                rule += f",\n\t\thasTrustLevel(Pod, {pre['trustLevel']})"
        rule += f"),\n\trule_desc('TECHNIQUE {t['id']} - {t['name']}',\n\t0.0)).\n"
        technique_rules.append(rule)

        # Extracting postconditions
        rule = ""
        for post in t_post[t["id"]]:           
            if post["type"] == "remoteAccess":
                goals.add(f"attackGoal(remoteAccess(_)).")
                rule = f"interaction_rule(\n\t(remoteAccess(Pod) :-\n\t{t['id']}_attack_step(Pod)),\n\trule_desc('COMPROMISED - Remote Access',\n\t0.0))."
            if post["type"] == "codeExec":
                goals.add(f"attackGoal(codeExec(_)).")
                rule = f"interaction_rule(\n\t(codeExec(Pod) :-\n\t{t['id']}_attack_step(Pod)),\n\trule_desc('COMPROMISED - Code Execution',\n\t0.0))."
            if post["type"] == "fileAccess":
                goals.add(f"attackGoal(fileAccess(_, _, _)).")
                perm = "_" if "perm" not in post or post["perm"] == "*" else post["perm"].lower()
                file = "_" if "file" not in post or post["file"] == "*" else f'\"{post["file"].lower()}\"'
                ruleDesc = "COMPROMISED - fileAccess" if perm != "_" else f"COMPROMISED - fileAccess ({perm})"
                rule = f"interaction_rule(\n\t(fileAccess(Pod, {file}, {perm}) :-\n\t{t['id']}_attack_step(Pod)),\n\trule_desc('{ruleDesc}',\n\t0.0))."
            if post["type"] == "dos":
                goals.add(f"attackGoal(dos(_)).")
                rule = f"interaction_rule(\n\t(dos(Pod) :-\n\t{t['id']}_attack_step(Pod)),\n\trule_desc('COMPROMISED - Denial of Service',\n\t0.0))."
            if post["type"] == "persistence":
                goals.add(f"attackGoal(persistence(_)).")
                rule = f"interaction_rule(\n\t(persistence(Pod) :-\n\t{t['id']}_attack_step(Pod)),\n\trule_desc('COMPROMISED - achieved Persistence',\n\t0.0))."
            if post["type"] == "dataManipulation":
                goals.add(f"attackGoal(dataManipulation(_)).")
                rule = f"interaction_rule(\n\t(dataManipulation(Pod) :-\n\t{t['id']}_attack_step(Pod)),\n\trule_desc('COMPROMISED - Data Manipulation',\n\t0.0))."
            if post["type"] == "privEscalation":
                goals.add(f"attackGoal(privilege(_, _)).")
                level = "_" if "level" not in post or post["level"] == "*" else post["level"].lower()
                rule = f"interaction_rule(\n\t(privilege(Pod, {level}) :-\n\t{t['id']}_attack_step(Pod)),\n\trule_desc('COMPROMISED - Privilege Esclation',\n\t0.0))."
            if post["type"] == "credentialAccess":
                goals.add(f"attackGoal(credentialAccess(_)).")
                account = "_" if "account" not in post or post["account"] == "*" else post["account"].lower()
                rule = f"interaction_rule(\n\t(credentialAccess({account}) :-\n\t{t['id']}_attack_step(Pod)),\n\trule_desc('COMPROMISED - Credential Access',\n\t0.0))."
        technique_rules.append(rule)
    return technique_facts, technique_rules, goals


def extract_network_info(pods):
    '''
    Extracts facts about the network policies of the Kubernetes infrastructure.
    If a pod specifies a default-allow behavior (denylist) rules are added allowing the traffic
    to and from the internet (rules denying traffic with specific ports or protocols from or to the internet
    are not considered).
    If a pod specifies a default-deny behavior (allowlist) rules allowing traffic flows are added if there is no
    corresponding rule (in another pod using a denylist) that denies such traffic flows (rules which allow traffic
    between pods with any port and protocol that are affected by other rules denying only certain ports/protocols
    are not considered). 

    args:
        pods: a list containing objects representing the pods of the Kubernetes infrastructure
    returns:
        list containing MulVAL facts describing the allowed traffic between 
        the pods of the infrastructure
    '''
    netRules = []
    for pod in pods:
        if "networkProperties" in pod and "restrictions" in pod["networkProperties"]:
            default_action = pod["networkProperties"]["restrictions"]["enforcement_behavior"]
            if "rules" in pod["networkProperties"]["restrictions"]:
                rules = pod["networkProperties"]["restrictions"]["rules"]
            if default_action == "default-allow":
                netRules.append(f'netRule({pod["label"].lower()}, internet, _, _, ingress).')
                netRules.append(f'netRule({pod["label"].lower()}, internet, _, _, egress).')
            elif default_action == "default-deny":
                if rules is None:
                    break
                for rule in rules:
                    direction = rule["direction"]
                    for proto in rule["proto"]:
                        for port in rule["port"]:
                            excluded = False
                            for p in pods:
                                if p["label"] == rule["label"] and p["networkProperties"]["restrictions"]["enforcement_behavior"] == "default-allow":
                                    if "rules" in p["networkProperties"]["restrictions"]:
                                        deny_rules = p["networkProperties"]["restrictions"]["rules"]
                                        for r in deny_rules:
                                            if  (r["label"] == pod["label"] and r["direction"] != direction and (port in r["port"] or r["port"] == "*") and (proto in r["proto"] or r["proto"] == "*")):
                                                excluded = True
                                    else:
                                        break
                            if not excluded:
                                port = "_" if port == "*" else port
                                proto = "_" if proto == "*" else proto
                                netRules.append(f'netRule({pod["label"].lower()}, {rule["label"].lower()}, {proto.lower()}, {port}, {direction.lower()}).')
    return netRules



def extract_infrastructure_inputs(infrastructure_path):
    '''
    Derives MulVAL facts from a JSON description of a Kubernetes infrastructure.

    args: 
        infrastructure_path: path to the JSON file describing the Kubernetes infrastructure.
        following the corresponding data model
    returns:
        extracted MulVAL facts describing the Kubernetes infrastructure.
    '''
    facts = []
    try:
        with open(infrastructure_path, 'r') as f:
            data = json.load(f)
            if data is None:
                print(f"No json data in {infrastructure_path}")
                return []

            pods = data["pods"]
            for pod in pods:
                if "libraries" in pod:
                    for lib in pod["libraries"]:
                        facts.append(f'hasLibrary({pod["label"].lower()}, {lib["name"].lower()}, {lib["version"]}).')
                        if "artifacts" in lib:
                            for art in lib["artifacts"]:
                                facts.append(f'hasArtifact({lib["name"].lower()}, {art["id"].replace(":","-").lower()}).')
                        if "vulnerabilities" in lib:
                            for vul in lib["vulnerabilities"]:
                                facts.append(f'vulExists({lib["name"].lower()}, {lib["version"]}, {vul["id"].lower()}).')
                if "serviceDependencies" in pod:
                    for dep in pod["serviceDependencies"]:
                        facts.append(f'dependsOn({pod["label"].lower()}, {dep["label"].lower()}).')
                if "networkProperties" in pod:
                    if "service" in pod["networkProperties"]:
                        service = pod["networkProperties"]["service"]
                        facts.append(f'exposesService({pod["label"].lower()}, {service["name"].lower()}, {service["protocol"].lower()}, {service["port"]}).')
                        if "artifacts" in service:
                            for art in service["artifacts"]:
                                facts.append(f'hasArtifact({service["name"].lower()}, {art["id"].replace(":","-").lower()}).')
                if "misconfigurations" in pod:
                    for m in pod["misconfigurations"]:
                        facts.append(f'misconfiguration({pod["label"].lower()}, {m["type"].lower()}).')
                if "mounts" in pod:
                    for m in pod["mounts"]:
                        facts.append(f'mounts({pod["label"].lower()}, {m["type"].lower()}, \"{m["path"]}\").')
                if "trustLevel" in pod:
                    facts.append(f'hasTrustLevel({pod["label"].lower(), pod["trustLevel"].lower()}).')

            facts = facts + extract_network_info(pods)
            return facts            

    
    except FileNotFoundError:
        print(f"File not found at {infrastructure_path}")
        return []
    except Exception as e:
        print(traceback.print_exc())
        return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("infrastructure_path", help="path to the JSON infrastructure representation")
    parser.add_argument("cti_path", help="path to STIX2.x Bundle")
    parser.add_argument("-l", "--location", help="allows to specify the label of a pod in which the attacker is located. By default the attackerLocated(internet)")
    parser.add_argument("-o", "--out", help="specify an output directory")
    parser.add_argument("-g", "--graph", action="store_true", help="generate attack graph from extracted inputs using MulVAL")
    args = parser.parse_args()
    
    infrastructure_path = os.path.join(os.getcwd(), args.infrastructure_path)
    cti_path = os.path.join(os.getcwd(), args.cti_path)
    out_dir = os.path.join(os.getcwd(), args.out) if args.out else os.getcwd()
    out_facts_path = os.path.join(out_dir, "extracted_facts.P")
    out_rules_path = os.path.join(out_dir, "extracted_rules.P")

    techniques = parse_cti(cti_path)

    attackerLocation = args.location if args.location else "internet"
    infrastructure_facts = extract_infrastructure_inputs(infrastructure_path)
    technique_facts, technique_rules, attack_goals = extract_technique_inputs(techniques)
    
    os.makedirs(out_dir, exist_ok=True)
    if infrastructure_facts:
        with open(out_facts_path, "w") as outfile:
            outfile.write(f"attackerLocated({attackerLocation}).\n")
            outfile.writelines([f"{goal}\n" for goal in attack_goals])
            outfile.writelines([f"{fact}\n" for fact in infrastructure_facts])
            outfile.writelines([f"{fact}\n" for fact in technique_facts])          
    else:
        print("No MulVAL inputs extracted from the infrastructure.")
    shutil.copyfile(os.path.join(os.path.dirname(__file__), "base_ruleset.P"), out_rules_path)
    with open(out_rules_path, "+a") as outfile:
        outfile.writelines([f"{rule}\n\n" for rule in technique_rules]) 

    if args.graph:
        p = subprocess.Popen(["graph_gen.sh", "extracted_facts.P", "-r", "extracted_rules.P", "-v", "-p"], cwd=out_dir)
        p.wait()



if __name__ == "__main__":
    main()