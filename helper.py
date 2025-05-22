import networkx as nx
import os
import json

#----- Helper functions for graphs

def decycle(AG):
    """
    Removes cycles from the graph

    Args:
        AG (networkx.DiGraph): Graph from which to remove cycles
    """
    cycles = list(nx.simple_cycles(AG))
    if not cycles:
        return
    for cycle in cycles:
        if cycle:
            AG.remove_edge(cycle[0], cycle[1])

def prune_graph(AG, inplace=False):
    """
    Prune the attack graph keeping only the most interesting nodes
    
    Args:
        AG (networkx.DiGraph): Graph to prune
        inplace (bool): Whether to prune a copy of the graph or the graph itself

    Returns:
        Pruned graph if not inplace or None
    """
    keep_labels = ["TECHNIQUE", "COMPROMISED", "attack_step", "attackerLocated", "vulExists",
                    "reachable", "codeExec", "fileAccess", "privilege", "credentialAccess", "mounts",
                    "remoteAccess", "codeExec", "dos", "persistence"]
    AG = AG if inplace else AG.copy()
    def _rec_pruning(n, in_n, nodes_to_keep, edges):
        for _, out_n in AG.out_edges(n):
            if out_n not in nodes_to_keep:
                _rec_pruning(out_n, in_n, nodes_to_keep, edges)
            else:
                edges.append((in_n, out_n))
    
    nodes_to_keep = [n[0] for n in AG.nodes.data() if any(map(n[1]["label"].__contains__, keep_labels))]
    pruned_edges = []
    for n in nodes_to_keep:
        _rec_pruning(n, n, nodes_to_keep, pruned_edges)
    AG.remove_nodes_from([n for n in AG.nodes if n not in nodes_to_keep])
    AG.clear_edges()
    AG.add_edges_from(pruned_edges)
    if not inplace:
        return AG
    
#----- Helper functions to get MITRE ATT&CK, D3FEND and DAO information from the KB

def get_attack_info(kb_path):
    """
    Read the contents related to ATT&CK from the Knowledge Base

    Returns:
        techniques: general information on ATT&CK Techniques
        t2c: mapping between ATT&CK Techniques and D3FEND Countermeasures
        t_pre: mapping between ATT&CK Techniques and their preconditions
        t_post: mapping between ATT&CK Techniques and their consequences
    """
    try:
        # Get general ATT&CK Technique info
        # ATT&CK to D3FEND mappings
        # Mappings between ATT&CK Techniques and pre/post-conditions
        with open(os.path.join(kb_path, "attack-techniques.json"), "r") as f:
            off_techniques = json.load(f)["techniques"]
            techniques = [{"id": t["id"], "name": t["name"], "definition": t["definition"]} for t in off_techniques]
            t2c = {}
            t_pre = {}
            t_post = {}
            for t in off_techniques:
                t2c[t["id"]] = t["countermeasures"]
                if "preconditions" in t:
                    t_pre[t["id"]] = t["preconditions"]
                if "postconditions" in t:
                    t_post[t["id"]] = t["postconditions"]
        return techniques, t2c, t_pre, t_post
    except FileNotFoundError as e:
        print(f"Unable to obtain ATT&CK informations from the Knowledge Base:\n{e}")
        return None, None, None, None 

def get_defend_info(kb_path):
    """
    Read the contents related to D3FEND from the Knowledge Base

    Returns:
        countermeasures: information on D3FEND Countermeasures
    """
    try:
        # Get D3FEND Technique info
        with open(os.path.join(kb_path, "defend-techniques.json"), "r") as f:
            countermeasures = json.load(f)["techniques"]
        return countermeasures
    except FileNotFoundError as e:
        print(f"Unable to obtain D3FEND information from the Knowledge Base:\n{e}")
        return None

def get_artifacts_info(kb_path):
    """
    Read the contents related to DAO artifacts from the Knowledge Base

    Returns:
        a2t: mapping between DAO artifacts and ATT&CK Techniques
        a2c: mapping between DAO artifacts and D3FEND Coundermeasures
    """
    try:
        # Get Artifact to ATT&CK and Artifact to D3FEND mappings
        with open(os.path.join(kb_path, "artifacts.json"), "r") as f:
            artifacts = json.load(f)["artifacts"]
            a2t = {}
            a2c = {}
            for a in artifacts:
                a2t[a["id"]] = a["da_to_off"]
                a2c[a["id"]] = a["da_to_def"]
        return a2t, a2c    
    except FileNotFoundError as e:
        print(f"Unable to DAO artifacts information from the Knowledge Base:\n {e}")
        return None, None