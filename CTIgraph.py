import os
import shutil
import subprocess
import json
import stix2
from networkx.drawing import nx_agraph

from GraphFormatter import AGFormatter
from helper import decycle, prune_graph, get_attack_info, get_artifacts_info


class MulValInputExtractor:
    """
    Generates MulVAL facts and rules from JSON representation of the Kubernetes infrastructure
    and ATT&CK Techniques extracted from the CTI report
    """
    def __init__(self, infrastructure_path, cti_path, output_dir=None, location=None, kb_path=None):
        """
        Initializes MulValInputExtractor.

        Args:
            infrastructure_path (str): path to the JSON representation of the infrastructure.
            cti_path (str): path to the STIX2.x Bundle.
            output_dir (str): directory to save the extracted facts and rules (defaults to cwd).
            location (str): attacker's starting location (defaults to internet).
        """
        self.infrastructure_path = infrastructure_path
        self.cti_path = cti_path
        cwd = os.getcwd()
        self.output_dir = cwd if output_dir is None else os.path.join(cwd, output_dir)
        self.location = "internet" if location is None else location.lower()
        kb_path = os.path.join(os.getcwd(), "kb") if kb_path is None else kb_path
        self.techniques, self.t2c, self.t_pre, self.t_post = get_attack_info(kb_path)
        self.a2t, _ = get_artifacts_info(kb_path)
        if self.techniques is None or self.a2t is None:
            raise Exception("Unable to initialize MulVAL Input Extractor:\nCould not read information from Knowledge Base")


    def _parse_cti(self):
        '''
        Parse a STIX2.x bundle looking for attack-pattern objects that represent a MITRE ATT&CK Technique and any 
        vulnerability object with related to them.

        returns:
            list of parsed ATT&CK Techniques in the form:
            [{'id': tid, 
            'name': technique_name
            'vulns': [cve_id1, cve_id2, ...]}, ...]
        '''
        techniques = []
        try:
            with open(self.cti_path, "r") as f:
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
            return techniques  
        except FileNotFoundError:
            print(f"File not found at {self.cti_path}")
            return []   
        except Exception as e:
            print(f"Error during CTI parsing: {e}")
            return []  


    def extract_technique_inputs(self):
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

        returns:
            technique_facts: MulVAL facts extracted from the techniques
            technique_rules: MulVAL rules extracted from the techniques
            goals: MulVAL facts representing the possible goals for the given set of techniques
        '''
        technique_facts = []
        technique_rules = []
        goals = set()
        technique_list = self._parse_cti()
        for t in technique_list:
            # if the technique is not in the kb skip it
            if t["id"] not in [technique["id"] for technique in self.techniques]:
                continue

            # table the derived technique rule
            technique_rules.append(f"derived({t['id']}_attack_step(_pod)).")
            technique_rules.append(f":- table {t['id']}_attack_step/1.")

            rule = f"interaction_rule(\n\t({t['id']}_attack_step(Pod) :-"
            for artid, tids in self.a2t.items():
                if t["id"] in tids:
                    # extract technique artifacts
                    technique_facts.append(f"techniqueArtifact({t['id']}, \'{artid.lower()}\').")
            if "vulns" in t:
                for v in t["vulns"]:
                    # extract techique exploited vulnerabilities
                    technique_facts.append(f"techniqueExploits({t['id']}, \'{v}\').")
                if t["vulns"]:
                    rule += f"\n\t\tpodExploitable(Pod, {t['id']})"  # add condition on artifacts+vulns if vulns present
                else: 
                    rule += f"\n\t\tpodTargetable(Pod, {t['id']})"
            else:
                rule += f"\n\t\tpodTargetable(Pod, {t['id']})"  # else consider only artifacts
            # require that the pod doesn't employ countermeasures against the technique
            if t["id"] in self.t2c:
                for dID in self.t2c[t["id"]]:
                    rule += f",\n\t\tnot hasCountermeasure(Pod, \'{dID.lower()}\')"
            # extract the various preconditions
            if t["id"] in self.t_pre:
                for pre in self.t_pre[t["id"]]:
                    if pre["type"] == "reachable":
                        port = "_" if "port" not in pre or pre["port"] == "*" else pre["port"]
                        proto = "_" if "proto" not in pre or pre["proto"] == "*" else pre["proto"].lower()
                        rule += f",\n\t\treachable(Pod, {proto}, {port})"
                    if pre["type"] == "codeExec":
                        rule += f",\n\t\tcodeExec(Pod)"
                    if pre["type"] == "fileAccess":
                        perm = "_" if "perm" not in pre or pre["perm"] == "*" else pre["perm"].lower()
                        file = "_" if "file" not in pre or pre["file"] == "*" else f"\'{pre['file']}\'"
                        rule += f",\n\t\tfileAccess(Pod, {file}, {perm})"
                    if pre["type"] == "privilege":
                        level = "_" if "level" not in pre or pre["level"] == "*" else pre["level"].lower()
                        rule += f",\n\t\tprivilege(Pod, {level})"
                    if pre["type"] == "credentialAccess":
                        account = "_" if "account" not in pre or pre["account"] == "*" else pre["account"].lower()
                        rule += f",\n\t\tcredentialAccess({account})"
                    if pre["type"] == "mounts":
                        kind = "_" if "kind" not in pre or pre["kind"] == "*" else pre["kind"].lower()
                        path = "_" if "path" not in pre or pre["path"] == "*" else f"\'{pre['path']}\'"
                        rule += f",\n\t\tmounts(Pod, {kind}, {path})"
            else:
                rule += f",\n\t\tunachievable({t['id']})"
            rule += f"),\n\trule_desc('TECHNIQUE {t['id']} - {t['name']}',\n\t0.0)).\n"
            technique_rules.append(rule)

            # Extracting postconditions
            # add each encountered compromission to 
            rule = ""
            if t["id"] in self.t_post:
                for post in self.t_post[t["id"]]:           
                    if post["type"] == "remoteAccess":
                        goals.add(f"attackGoal(remoteAccess(_)).")
                        rule = f"interaction_rule(\n\t(remoteAccess(Pod) :-\n\t{t['id']}_attack_step(Pod)),\n\trule_desc('COMPROMISED - Remote Access',\n\t0.0))."
                    if post["type"] == "codeExec":
                        goals.add(f"attackGoal(codeExec(_)).")
                        rule = f"interaction_rule(\n\t(codeExec(Pod) :-\n\t{t['id']}_attack_step(Pod)),\n\trule_desc('COMPROMISED - Code Execution',\n\t0.0))."
                    if post["type"] == "fileAccess":
                        goals.add(f"attackGoal(fileAccess(_, _, _)).")
                        perm = "_" if "perm" not in post or post["perm"] == "*" else post["perm"].lower()
                        file = "_" if "file" not in post or post["file"] == "*" else f"\'{post['file']}\'"
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


    def extract_infrastructure_inputs(self):
        """
        Derives MulVAL facts from a JSON description of a Kubernetes infrastructure.
        The facts derived include:
            hasLibrary(pod, libName, libVer). -> a pod uses a certain version of a library
            hasArtifact(libName, artID). -> a library is associated to a D3FEND artifact
            vulExists(libName, libVer, cveID). -> a given version of a library is affected by a vulnerability
            dependsOn(pod, dependencyPod). -> indicates the dependency of a pod to another
            exposesService(pod, service, protocol, port). -> describes a service exposed by the pod
            hasArtifact(service, artID) -> a service is associated to a D3FEND artifact
            netRule(pod, target, proto, port, direction, action) -> models a network policy, allow/deny, between pod and target
            mounts(pod, type, path). -> indicates a mounted volume
            hasCountermeasure(pod, d3fendID) -> the pod uses a D3FEND countermeasure

        returns:
            list of strings representing MulVAL facts modeling the Kubernetes infrastructure.
        """
        facts = []
        try:
            # Load infrastructure data from the JSON file
            with open(self.infrastructure_path, 'r') as f:
                data = json.load(f)
                if data is None:
                    print(f"No infrastructure data in {os.path.basename(self.infrastructure_path)}")
                    return []

                # For each pod extract facts from its JSON representation
                pods = data["pods"]
                for pod in pods:
                    # Extract library-related facts:
                    # this includes the association between pod and library,
                    # the association between library and D3FEND artifact,
                    # and the presence of a vulnerability in a given library version
                    if "libraries" in pod:
                        for lib in pod["libraries"]:
                            facts.append(f"hasLibrary({pod['label'].lower()}, \'{lib['name'].lower()}\', \'{lib['version']}\').")
                            if "artifacts" in lib:
                                for art in lib["artifacts"]:
                                    facts.append(f"hasArtifact(\'{lib['name'].lower()}\', \'{art['id'].lower()}\').")
                            if "vulnerabilities" in lib:
                                for vul in lib["vulnerabilities"]:
                                    facts.append(f"vulExists(\'{lib['name'].lower()}\', \'{lib['version']}\', \'{vul['id'].lower()}\').")
                    # Extract the service dependencies of a pod
                    if "serviceDependencies" in pod:
                        for dep in pod["serviceDependencies"]:
                            facts.append(f'dependsOn({pod["label"].lower()}, {dep["label"].lower()}).')
                    # Extract facts related to the pod's network properties:
                    # this includes the exposed service,
                    # the association between service and D3FEND artifact
                    # the network policies of the pod
                    if "networkProperties" in pod:
                        if "service" in pod["networkProperties"]:
                            service = pod["networkProperties"]["service"]
                            facts.append(f'exposesService({pod["label"].lower()}, {service["name"].lower()}, {service["protocol"].lower()}, {service["port"]}).')
                            if "artifacts" in service:
                                for art in service["artifacts"]:
                                    facts.append(f"hasArtifact({service['name'].lower()}, \'{art['id'].lower()}\').")
                        if "restrictions" in pod["networkProperties"]:
                            default_action = pod["networkProperties"]["restrictions"]["enforcement_behavior"]
                            if "rules" in pod["networkProperties"]["restrictions"]:
                                rules = pod["networkProperties"]["restrictions"]["rules"]
                                if default_action == "default-allow":
                                    facts.append(f'netRule({pod["label"].lower()}, _, _, _, _, allow).')
                                for rule in rules:
                                    dir = rule["direction"].lower()
                                    for proto in rule["proto"]:
                                        for port in rule["port"]:
                                            proto = "_" if proto == "*" else proto.lower()
                                            port = "_" if port == "*" else port
                                            action = rule["action"].lower()
                                            if rule["type"].lower() == "pod":
                                                target = rule["label"].lower() 
                                                facts.append(f'netRule({pod["label"].lower()}, {target}, {proto}, {port}, {dir}, {action}).')
                                            else: 
                                                facts.append(f'netRule({pod["label"].lower()}, internet {proto}, {port}, {dir}, {action}).')
                    # Extract information about the mounted volumes
                    if "mounts" in pod:
                        for m in pod["mounts"]:
                            facts.append(f"mounts({pod['label'].lower()}, {m['type'].lower()}, \'{m['path']}\').")
                    # Extract information on the employed countermeasures
                    if "countermeasures" in pod:
                        for dID in pod["countermeasures"]:
                            facts.append(f"hasCountermeasure({pod['label']}, \'{dID.lower()}\').")
                return facts  
        except FileNotFoundError:
            print(f"File not found at {self.infrastructure_path}")
            return []
        except Exception as e:
            print(f"Error: {e}")
            return []
        

    def extract_MulVal_inputs(self):
        """
        Extracts MulVAL facts and rules and outputs them in "extracted_facts.P" and "extracted_rules.P"
        """
        out_facts_path = os.path.join(self.output_dir, "extracted_facts.P")
        out_rules_path = os.path.join(self.output_dir, "extracted_rules.P")
        os.makedirs(self.output_dir, exist_ok=True)

        # Extract facts and rules
        infrastructure_facts = self.extract_infrastructure_inputs()
        technique_facts, technique_rules, attack_goals = self.extract_technique_inputs()

        # Write the extracted files to "extracted_facts.P"
        # also write facts about the attacker location and attack goals
        with open(out_facts_path, "w") as outfile:
            outfile.write(f"attackerLocated({self.location}).\n")
            outfile.writelines([f"{goal}\n" for goal in attack_goals])
            outfile.writelines([f"{fact}\n" for fact in infrastructure_facts])
            outfile.writelines([f"{fact}\n" for fact in technique_facts])
        # Copy the base ruleset to "extracted_rules.P" and append the extracted rules to it
        shutil.copyfile(os.path.join(os.path.dirname(__file__), "base_ruleset.P"), out_rules_path)
        with open(out_rules_path, "+a") as outfile:
            outfile.writelines([f"{rule}\n\n" for rule in technique_rules]) 


class AttackGraphGenerator:
    """
    Generates an attack graph using MulVAL
    """

    def __init__(self, input_facts, input_rules, output_dir=None):
        """
        Initializes the AttackGraphGenerator.

        Args:
            input_facts (str): path to the file containing MulVAL inputs.
            input_rules (str): path to the file containing MulVAL rules.
            output_dir (str): directory to store MulVAL inputs and the generated attack graph.
        """
        cwd = os.getcwd()
        input_facts = os.path.join(cwd, input_facts)
        input_rules = os.path.join(cwd, input_rules)
        if not os.path.isfile(input_facts) or not os.path.isfile(input_rules):
            raise FileNotFoundError("Input files not found")
        self.output_dir = cwd if output_dir is None else os.path.join(cwd, output_dir)


    def _cleaner(self):
        """
        Removes useless MulVAL outputs
        """
        to_remove = ["ARCS.CSV", "VERTICES.CSV", "AttackGraph.eps", "AttackGraph.txt", "AttackGraph.xml",
                "dynamic_decl.gen", "environment.P", "environment.xwam", "metric.P",
                "run.P", "run.xwam", "running_rules.P", "trace_output.P", "translated_rules.P", "xsb_log.txt"]
        for filename in to_remove:
            file_path = os.path.join(self.output_dir, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)


    def gen_graph(self, no_prune=False, to_flow=False, cleanup=True, to_mermaid=False):
        """
        Generate the attack graph from the extracted inputs.

        Args:
            unprune (bool): don't apply pruning to the attack graph (defaults to False).
            to_flow (bool): generate an ATTACK-FLOW-like representation of the graph (defaults to False).
            to_mermaid (bool): generate a mermaid representation of the graph (defaults to False).
            cleanup (bool): removes unnecessary output files from MulVAL (defaults to True).

        Returns:
            AG: NetworkX Graph representing the Attack Graph
            None: if no graph was generated
        """
        ag_path = os.path.join(self.output_dir, "AttackGraph.dot")
        if no_prune:
            p = subprocess.Popen(["graph_gen.sh", "extracted_facts.P", "-r", "extracted_rules.P", "-v", "-p"], 
                                cwd=self.output_dir, 
                                stdout=subprocess.DEVNULL)
            p.wait()
            if not os.path.isfile(ag_path):
                print("No Attack Graph was generated")
                return
            else:
                AG = nx_agraph.read_dot(ag_path)
        else:
            p = subprocess.Popen(["graph_gen.sh", "extracted_facts.P", "-r", "extracted_rules.P", "-v", "-p", "--nopdf", "--nometric"], 
                                cwd=self.output_dir, 
                                stdout=subprocess.DEVNULL)
            p.wait()
            if not os.path.isfile(ag_path):
                print("No Attack Graph was generated")
                return
            else:
                AG = nx_agraph.read_dot(ag_path)
                prune_graph(AG, inplace=True)
                decycle(AG)
                nx_agraph.write_dot(AG, ag_path)
                p = subprocess.Popen(["dot", "-Tpdf", "AttackGraph.dot", "-o", "AttackGraph.pdf"],
                            cwd=self.output_dir)
                p.wait()
        if cleanup:
            # Remove MulVAL outputs
            self._cleaner()
        if to_flow:
            # Read and prune the graph to turn to FLOW
            G = prune_graph(AG)
            decycle(G)
            formatter = AGFormatter(self.output_dir, G)
            formatter.to_flow()
        if to_mermaid:
            # Read and prune the graph to turn to mermaid
            G = prune_graph(AG)
            decycle(G)
            formatter = AGFormatter(self.output_dir, G)
            formatter.to_mermaid()
        return AG