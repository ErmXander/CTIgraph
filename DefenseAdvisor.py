import os
import json
import re

import networkx as nx

from helper import get_attack_info, get_defend_info, get_artifacts_info, decycle, prune_graph


class DefenseAdvisor:
    """
    Provides a set of countermeasures to apply to the infrastructure to address
    the attack paths from a given Attack Graph 
    """

    def __init__(self, infrastructure_path, kb_path=None, output_dir=None):
        """
        Initializes the DefenseAdvisor

        Args:
            infrastructure_path (string): path to the JSON representation of the Kubernetes Infrastructure
            output_dir (string): path to the directory in which to save the output
            excluded_pods (list<string>): list of pod labels which should not be considered
            excluded_countermeasures (list<string>): list of D3FEND Techniques ids which should not be considered
            exclusion_map (dict<string,list<string>>): dict listing the D3FEND Techniques which should not be
                considered when looking for the countermeasures to apply to specific pods
        """
        cwd = os.getcwd()
        infrastructure_path = os.path.join(cwd, infrastructure_path)
        try:
            with open(infrastructure_path, "r") as f:
                self.infrastructure = json.load(f)
        except FileNotFoundError as e:
            raise Exception(f"Could not initialize Defense Advisor:\n{e}")
        self.output_dir = cwd if output_dir is None else os.path.join(cwd, output_dir)
        kb_path = os.path.join(os.getcwd(), "kb") if kb_path is None else kb_path
        _, self.t2c, _, _ = get_attack_info(kb_path)
        self.countermeasures = get_defend_info(kb_path)
        _, self.a2c = get_artifacts_info(kb_path)

    
    def _get_pod_artifacts(self, pod):
        """
        Gets the artifacts associated to the pod

        Args:
            pod (string): label of the pod
        Returns:
            list of artifact identifiers
        """
        pod = next((p for p in self.infrastructure["pods"] if p["label"]==pod), None)
        if pod is None:
            return []
        artifacts = []
        libraries = pod["libraries"]
        for l in libraries:
            if "artifacts" in l:
                artifacts.extend([a["id"] for a in l["artifacts"]])
        net_props = pod["networkProperties"]
        if "artifacts" in net_props["service"]:
            artifacts.extend([a["id"] for a in net_props["service"]["artifacts"]])
        return list(set(artifacts))


    def getCountermeasures(self, AG, excluded_pods=[], excluded_countermeasures=[], exclusion_map={}):
        """
        Get the countermeasures to apply to remove the attack paths from the graph

        Args:
            excluded_pods (list<string>): list of pod labels which should not be considered
            excluded_countermeasures (list<string>): list of D3FEND Techniques ids which should not be considered
            exclusion_map (dict<string,list<string>>): dict listing the D3FEND Techniques which should not be
                considered when looking for the countermeasures to apply to specific pods
        """
        def _rec_counter(n, countermeasures, G):
            # Get next nodes
            out_nodes = [out_n for _, out_n in G.out_edges(n[0])]
            out_nodes = [out_n for out_n in G.nodes.data() if out_n[0] in out_nodes]
            if "attack_" in n[1]["label"]:
                # Technique Execution node found
                if t_match := re.search(':(.*)_attack_step\((.*)\)', n[1]["label"]):
                    tid = t_match.group(1)
                    pod = t_match.group(2)
                # Check if this node is reachable:
                # the node is not reachable if at least of the conditions 
                # for the derivation of this node is not reachable
                reachable = True
                derivation_node = next((in_n for in_n, _ in G.in_edges(n[0])), None)
                for in_n, _ in G.in_edges(derivation_node):
                    if G.in_degree(in_n) == 0:
                        reachable = False
                        break
                if not reachable:
                    G.remove_node(n[0]) # Remove unreachable node
                    if n[0] in countermeasures: 
                        # Remove any countermeasure that may have been added on a previous visit of the node
                        countermeasures.pop(n[0])
                elif pod not in excluded_pods: # Do not consider the pod if it needs to be excluded
                    # Get available countermeasures for the technique to apply to the pod
                    pod_arts = self._get_pod_artifacts(pod)
                    tech_counters = self.t2c[tid]
                    available_counters = []
                    for a in pod_arts:
                        counters = self.a2c[a] # Get the countermeasures applicable to the pod given its artifacts
                        counters = [c["id"] for c in self.countermeasures if c["name"] in counters]
                        # Add any applicable countermeasure that can defend from the technique
                        available_counters.extend([c for c in counters if c in tech_counters])
                    # Remove techniques to be excluded
                    available_counters = [ac for ac in available_counters if ac not in excluded_countermeasures]
                    available_counters = [ac for ac in available_counters if pod not in exclusion_map or ac not in exclusion_map[pod]]
                    if available_counters:
                        # If the step can be countered remove the node
                        G.remove_node(str(n[0]))
                        countermeasures[n[0]] = list(set(available_counters))
            for out_node in out_nodes:
                _rec_counter(out_node, countermeasures, G)

        # Preprocess graph
        G = prune_graph(AG)
        decycle(G)
        # Find attackerLocation node
        root_node = next((n for n in G.nodes.data() if "attackerLocated" in n[1]["label"]), None)
        countermeasures = {}
        # Recursively get the countermeasures for each node
        _rec_counter(root_node, countermeasures, G)
        # Get the set of suggested defensive techniques for each pod
        suggestions = {}
        for n, counters in countermeasures.items():
            if t_match := re.search(':(.*)_attack_step\((.*)\)', AG.nodes[n]["label"]):
                    pod = t_match.group(2)
            if pod not in suggestions:
                suggestions[pod] = []
            suggestions[pod].extend(counters)
        # Write the results to file
        with open(os.path.join(self.output_dir, "d3fend_suggestions.json"), "w") as f:
            json.dump(suggestions, f, indent=3)