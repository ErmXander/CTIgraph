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


    def _build_tech_graph(self, AG):
        """
        Build a graph containing only technique execution nodes

        Args:
            AG (networkx.DiGraph): Attack Graph
        Returns:
            TG (networkx.DiGraph): Technique Graph
        """
        TG = nx.DiGraph()
        def _rec_building(n, in_n, nodes_to_keep, edges):
            for _, out_n in AG.out_edges(n):
                if out_n not in nodes_to_keep:
                    _rec_building(out_n, in_n, nodes_to_keep, edges)
                else:
                    edges.append((in_n, out_n))
        
        # Keep only {TID}_attack_step({pod}) nodes
        nodes_to_keep = [n[0] for n in AG.nodes.data() if "attack_" in n[1]["label"]]
        edges = []
        for n in nodes_to_keep:
            _rec_building(n, n, nodes_to_keep, edges)
        nodes_to_keep = [n for n in AG.nodes.data() if n[0] in nodes_to_keep]
        tech_nodes = []
        for n in nodes_to_keep:
            if t_match := re.search(':(.*)_attack_step\((.*)\)', n[1]["label"]):
                tid = t_match.group(1)
                pod = t_match.group(2)
                tech_nodes.append((n[0], {"tid": tid, "pod": pod}))
        TG.add_nodes_from(tech_nodes)
        TG.add_edges_from(edges)
        return TG

    
    def getCountermeasures(self, AG, excluded_pods=[], excluded_countermeasures=[], exclusion_map={}):
        """
        Get the countermeasures to apply to remove the attack paths from the graph

        Args:
            excluded_pods (list<string>): list of pod labels which should not be considered
            excluded_countermeasures (list<string>): list of D3FEND Techniques ids which should not be considered
            exclusion_map (dict<string,list<string>>): dict listing the D3FEND Techniques which should not be
                considered when looking for the countermeasures to apply to specific pods
        """
        def _rec_counter(n, countermeasures, root_nodes):
            # Get next technique nodes
            out_nodes = [out_n for _, out_n in TG.out_edges(n[0])]
            out_nodes = [out_n for out_n in TG.nodes.data() if out_n[0] in out_nodes]
            # If a node is not a root node and has in_degree=0 it is no longer reachable
            if n[0] not in [r[0] for r in root_nodes] and TG.in_degree(n[0])==0:
                TG.remove_node(n[0]) # Remove unreachable node
                if n[1]["pod"] in countermeasures and n[1]["tid"] in countermeasures[n[1]["pod"]]: 
                    # Remove any countermeasure that may have been added on a previous visit of the node
                    # needed for the nodes that can be reached from multiple different nodes
                    countermeasures[n[1]["pod"]].pop(n[1]["tid"])
            elif n[1]["pod"] not in excluded_pods: # Skip the countermeasure evaluation if pod has to be ignored
                # Get available countermeasures for the technique to apply to the pod
                pod_arts = self._get_pod_artifacts(n[1]["pod"])
                tech_counters = self.t2c[n[1]["tid"]]
                available_counters = []
                for a in pod_arts:
                    counters = self.a2c[a] # Get the countermeasures applicable to the pod given its artifacts
                    counters = [c["id"] for c in self.countermeasures if c["name"] in counters]
                    # Add any applicable countermeasure that can defend from the technique
                    available_counters.extend([c for c in counters if c in tech_counters])
                # Remove techniques to be excluded
                available_counters = [ac for ac in available_counters if ac not in excluded_countermeasures]
                available_counters = [ac for ac in available_counters if n[1]["pod"] not in exclusion_map or ac not in exclusion_map[n[1]["pod"]]]
                if available_counters:
                    # If the step can be countered remove the node
                    TG.remove_node(n[0])
                    countermeasures[n[1]["pod"]] = {}
                    countermeasures[n[1]["pod"]][n[1]["tid"]] = list(set(available_counters)) 
            for out_n in out_nodes: # Proceed downstream
                _rec_counter(out_n, countermeasures, root_nodes)

        # Build Technique Graph
        TG = prune_graph(AG)
        decycle(TG)
        TG = self._build_tech_graph(AG)
        # Find "root" nodes
        root_nodes = [r for r in TG.nodes.data() if r[0] in [n for n, d in TG.in_degree() if d==0]]
        countermeasures = {}
        # Recursively get the countermeasures for each node
        for rn in root_nodes:
            _rec_counter(rn, countermeasures, root_nodes)
        # Get the set of suggested defensive techniques for each pod
        suggestions = {}
        for pod, counters in countermeasures.items():
            if counters:
                suggestions[pod] = []
                for cs in counters.values():
                    suggestions[pod].extend(cs)
                suggestions[pod] = list(set(suggestions[pod]))
        # Write the results to file
        with open(os.path.join(self.output_dir, "d3fend_suggestions.json"), "w") as f:
            json.dump(suggestions, f, indent=3)