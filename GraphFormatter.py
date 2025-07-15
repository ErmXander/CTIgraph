import re
import stix2
import os.path
from networkx.drawing import nx_agraph
import networkx as nx
from helper import get_logger
import subprocess
logger = get_logger(__name__)

#---------Custom Object definitions for ATTACK FLOW

_AttackFlowExtentionDefinition = stix2.ExtensionDefinition(
    id = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4",
    spec_version = "2.1",
    created = "2022-08-02T19:34:35.143Z",
    modified = "2022-08-02T19:34:35.143Z",
    name = "Attack Flow",
    description = "Extends STIX 2.1 with features to create Attack Flows.",
    created_by_ref = "identity--fb9c968a-745b-4ade-9b25-c324172197f4",
    schema = "https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json",
    version ="2.0.0",
    extension_types = [
        "new-sdo"
    ]
)

@stix2.CustomObject(
    "attack-flow", [
        ("name", stix2.properties.StringProperty(required=True)),
        ("description", stix2.properties.StringProperty()),
        ("scope", stix2.properties.EnumProperty(allowed="attack-tree")),
        ("start_refs", stix2.properties.ListProperty(required= True, contained=stix2.properties.ReferenceProperty(valid_types=["attack-action"]))),
        ("extensions", stix2.properties.ExtensionsProperty(required=True))
    ]
)
class _AttackFlow:
    pass

@stix2.CustomObject(
    "attack-action", [
        ("name", stix2.properties.StringProperty(required=True)),
        ("description", stix2.properties.StringProperty()),
        ("tactic_id", stix2.properties.StringProperty()),
        ("tactic_ref", stix2.properties.ReferenceProperty(valid_types="x-mitre-tactic")),
        ("technique_id", stix2.properties.StringProperty()),
        ("technique_ref", stix2.properties.ReferenceProperty(valid_types="attack-pattern")),
        ("asset_refs", stix2.properties.ListProperty(contained=stix2.properties.ReferenceProperty("attack-asset"))),
        ("effects_refs", stix2.properties.ListProperty(contained=stix2.properties.ReferenceProperty(valid_types=["attack-action"]))),
        ("extensions", stix2.properties.ExtensionsProperty(required=True))
    ]
)
class _AttackAction:
    pass

@stix2.CustomObject(
    "attack-asset", [
        ("name", stix2.properties.StringProperty(required=True)),
        ("description", stix2.properties.StringProperty()),
        ("extensions", stix2.properties.ExtensionsProperty(required=True))
    ]
)
class _AttackAsset:
    pass

#---------Mermaid class definitions
_mmd_attackerClass = "\tclassDef attacker fill:#faa ,stroke:#f21,stroke-width:2px;\n"
_mmd_techniqueClass = "\tclassDef technique fill:#fca ,stroke:#f81,stroke-width:2px;\n"
_mmd_vulnClass = "\tclassDef vulnerability fill:#fea ,stroke:#fd2,stroke-width:2px;\n"
#----------


class AGFormatter:
    """
    Allows to translate the Attack Graph to different formats

    Args:
        out_dir: path to the directory in which to save the outputs
        AttackGraph: NetworkX graph representing the Attack Graph
        dot_path: path to the .dot file describing the Attack Graph
    """

    def __init__(self, out_dir, AttackGraph=None, dot_path=None):
        self.out_dir = out_dir
        if AttackGraph:
            self.AG = AttackGraph
        elif dot_path is not None:
            self.AG = nx_agraph.read_dot(dot_path)
        else:
            raise Exception("Cannot initialize the AttackGraph Formatter:\n" \
            "No AttackGraph was provided")

    
    def to_flow(self):
        """
        Generate the ATTACK FLOW representation from the attack graph
        """
        logger.info("Converting Graph to AttackFlow")
        def _rec_build(n, prev_n, next_nodes):
            """
            Recursively find the technique nodes and build the ATTACK FLOW Graph
            """
            # Check if the current node is a technique rule derivation
            if "TECHNIQUE" in n[1]["label"] and n[0] not in added_nodes:
                # Extract technique info
                if t_match := re.search(r'\(TECHNIQUE (.*) - (.*)\)', n[1]["label"]):
                    tid = t_match.group(1)
                    tname = t_match.group(2)
                # Extract compromised pod label
                out_n = list(self.AG.out_edges(n[0]))[0][1]
                out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                if pod := re.search(r'step\((.*)\)', out_n[1]["label"]):
                    pod = pod.group(1)
                # Extract attack_step consequences
                cons_desc = ""
                for _, cons_n in self.AG.out_edges(out_n[0]):
                    cons_n = [n for n in self.AG.nodes.data() if n[0]==cons_n][0]
                    if consequence := re.search(r'\((.*)\)' ,cons_n[1]["label"]):
                        consequence = consequence.group(1)
                        cons_desc += f"\n{consequence}"
                if cons_desc:
                    cons_desc = f"Consequences of the technique:{cons_desc}"
                # Extract exploited vulnerabilities
                vuls = []
                for in_n, _ in self.AG.in_edges(n[0]):
                    in_n = [n for n in self.AG.nodes.data() if n[0]==in_n][0]
                    if "vulExists" in in_n[1]["label"]:
                        if vul_id := re.search(r'vulExists\(.*,(.*)\)', in_n[1]["label"]):
                            vul_id = vul_id.group(1)
                        vuls.append(stix2.Vulnerability(name=vul_id))
                # Proceed downsream using current node as prev_n appending any found techniques to attack_effects
                attack_effects = []
                for _, out_n in self.AG.out_edges(n[0]):
                    out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                    _rec_build(out_n, n, attack_effects)
                # Create the SDOs for the pod, the attack_action and the relationship to the vulnerabilities
                # and add all objects to flow_objects
                asset_node = _AttackAsset(
                    name=pod,
                    extensions = {
                        "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4": {
                            "extension_type": "new-sdo"
                        }
                    }    
                )
                flow_objects.append(asset_node)
                attack_action = _AttackAction(
                    name = tname,
                    technique_id = tid,
                    asset_refs = [asset_node],
                    description = cons_desc,
                    effects_refs = attack_effects,
                    extensions = {
                        "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4": {
                            "extension_type": "new-sdo"
                        }
                    }
                )
                flow_objects.append(attack_action)
                for v in vuls:
                    relationship = stix2.Relationship(
                        source_ref = v.id,
                        target_ref = attack_action.id,
                        relationship_type = "related_to"
                    )
                    flow_objects.append(relationship)
                flow_objects.extend(vuls)

                added_nodes.append(n[0])

                # If there's no prior attack_action node add this as a start node
                # Otherwise append the current attack_action.id to the previous one's next attack_action
                if prev_n is None:
                    start_nodes.append(attack_action)
                # Append the current node to the effects of the previous attack-action
                if next_nodes is not None:
                    next_nodes.append(attack_action.id)
            
            # The current node is not a technique derivation node
            # Proceed downstream with prev_n and next_nodes unchanged
            else:
                for _, out_n in self.AG.out_edges(n[0]):
                    out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                    _rec_build(out_n, prev_n, next_nodes)

        # Find the 1st node, attackerLocated, and create a ThreatActor SDO for it
        location_node = [n for n in self.AG.nodes.data() if "attackerLocated" in n[1]["label"]][0]
        if location := re.search(r'attackerLocated\((.*)\)', location_node[1]["label"]):
            location = location.group(1)
        attacker_node = stix2.ThreatActor(name="Attacker", description=f"Located in {location}")
        # Store the Attack FLOW objects
        flow_objects = []
        # Store the entrypoints of FLOW
        start_nodes = []
        #Keep track of already inserted nodes to avoid considering a technique twice when recurring
        added_nodes = []
        # Recursively build the Attack FLoW graph starting from attackerLocation
        _rec_build(location_node, prev_n=None, next_nodes=None)
        # Link the attacker to the first attack_actions
        for action in start_nodes:
            relationship = stix2.Relationship(
                source_ref = attacker_node.id,
                target_ref = action.id,
                relationship_type = "related_to"
            )
            flow_objects.append(relationship)
        # Generate the AttackFlow SDO and Bundle
        attack_flow = _AttackFlow(
            name = "Flow-ized AttackGraph",
            scope = "attack-tree",
            start_refs = [action.id for action in start_nodes],
            extensions = {
                "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4": {
                    "extension_type": "new-sdo"
                }
            }
        )
        flow_objects.insert(0, attacker_node)
        flow_objects.insert(0, attack_flow)
        flow_objects.insert(0, _AttackFlowExtentionDefinition)
        bundle = stix2.Bundle(flow_objects)

        # Write bundle to file
        outfile = os.path.join(self.out_dir, "AttackGraph.json")
        with open(outfile, "w") as f:
            f.write(bundle.serialize(pretty=True))
        

    def to_mermaid(self):
        """
        Generate a mermaid representation of the Attack Graph
        """

        logger.info("Converting Graph to Mermaid")
        def _rec_build(n, prev_n):
            """
            Recursively find the technique nodes and build the Mermaid Graph
            """
            # Check if the current node is a technique rule derivation
            if "TECHNIQUE" in n[1]["label"] and n[0] not in added_nodes:
                # Extract technique info
                if t_match := re.search(r'\(TECHNIQUE (.*) - (.*)\)', n[1]["label"]):
                    tid = t_match.group(1)
                    tname = t_match.group(2)
                    technique_nodes.append((n[0], f"{tname}<br>&lt{tid}&gt"))
                edges.append(f"{prev_n[0]}--->{n[0]}\n")
                # Extract compromised pod label
                out_n = list(self.AG.out_edges(n[0]))[0][1]
                out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                if pod := re.search(r'step\((.*)\)', out_n[1]["label"]):
                    pod = pod.group(1)
                # Extract attack_step consequences
                for _, cons_n in self.AG.out_edges(out_n[0]):
                    cons_n = [n for n in self.AG.nodes.data() if n[0]==cons_n][0]
                    if consequence := re.search(r'\(COMPROMISED - (.*)\)' ,cons_n[1]["label"]):
                        consequence = consequence.group(1)
                        consequence_nodes.append((cons_n[0], f"{consequence}<br>&lt{pod}&gt"))
                        edges.append(f"{n[0]}-->|compromise|{cons_n[0]}\n")
                # Extract exploited vulnerabilities
                for in_n, _ in self.AG.in_edges(n[0]):
                    in_n = [n for n in self.AG.nodes.data() if n[0]==in_n][0]
                    if "vulExists" in in_n[1]["label"]:
                        if vul_id := re.search(r'vulExists\(.*,(.*)\)', in_n[1]["label"]):
                            vul_id = vul_id.group(1)
                            vuln_nodes.append((in_n[0],f"{vul_id}<br>&lt{pod}&gt"))
                            edges.append(f"{in_n[0]}-->{n[0]}\n")
                added_nodes.append(n[0])
                # Proceed downstram with the current node as prev_n
                for _, out_n in self.AG.out_edges(n[0]):
                    out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                    _rec_build(out_n, n)
            elif "COMPROMISED" in n[1]["label"]:
                # Proceed downstream with the current node as prev_n
                for _, out_n in self.AG.out_edges(n[0]):
                    out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                    _rec_build(out_n, n)
            else:
                # Proceed downstream with the same prev_n
                for _, out_n in self.AG.out_edges(n[0]):
                    out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                    _rec_build(out_n, prev_n)
        # Find the 1st node, attackerLocated
        location_node = [n for n in self.AG.nodes.data() if "attackerLocated" in n[1]["label"]][0]
        if location := re.search(r'attackerLocated\((.*)\)', location_node[1]["label"]):
            location = location.group(1)
        # For each node store its id and a label
        attacker_node = (location_node[0], f"ATTACKER<br>&lt{location}&gt")
        technique_nodes = []
        vuln_nodes = []
        consequence_nodes = []
        edges = []
        #Keep track of already inserted nodes to avoid considering a technique twice when recurring
        added_nodes = []
        # Recursively build the mermaid graph starting from attackerLocation
        _rec_build(location_node, location_node)
        # Write to file
        outfile = os.path.join(self.out_dir, "AttackGraph.mmd")
        with open(outfile, "w") as f:
            f.writelines(["flowchart TD\n", _mmd_attackerClass, _mmd_techniqueClass, _mmd_vulnClass])
            attacker = '\t{0}:::attacker@{{ shape: stadium, label: "{1}" }}\n'.format(attacker_node[0], attacker_node[1])
            f.write(attacker)
            for t_node in technique_nodes:
                technique = '\t{0}:::technique@{{ shape: rounded, label: "{1}" }}\n'.format(t_node[0], t_node[1])
                f.write(technique)
            for v_node in vuln_nodes:
                vuln = '\t{0}:::vulnerability@{{ shape: circle, label: "{1}" }}\n'.format(v_node[0], v_node[1])
                f.write(vuln)
            for c_node in consequence_nodes:
                consequence = '\t{0}:::vulnerability@{{ shape: stadium, label: "{1}" }}\n'.format(c_node[0], c_node[1])
                f.write(consequence)
            f.writelines(edges)

    

    def _get_viz_attacker(self, node_id, location, label=None):
        formatted_node = "<TR><TD COLSPAN=\"2\" BGCOLOR=\"red\"><B>ATTACKER</B></TD></TR>"
        if label:
            label_row = f"<TR><TD COLSPAN=\"2\">{label}</TD></TR>"
            formatted_node = f"{formatted_node}\n{label_row}"
        location_row = f"""
        <TR>
            <TD ALIGN="LEFT"><B>Location</B></TD>
            <TD ALIGN="LEFT">{location}</TD>
        </TR>"""
        formatted_node = f"<<TABLE BORDER =\"1\" CELLBORDER=\"1\" CELLSPACING=\"0\">{formatted_node}{location_row}</TABLE>>"
        return formatted_node
    
    def _get_viz_technique(self, node_id, tid, tname, pod, label=None, probability=None):
        formatted_node = """
        <TR><TD COLSPAN=\"2\" BGCOLOR=\"orange\"><B>TECHNIQUE</B></TD></TR>
        """
        if label:
            label_row = f"<TR><TD COLSPAN=\"2\">{label}</TD></TR>"
            formatted_node = f"{formatted_node}\n{label_row}"
        formatted_node = f"""
        {formatted_node}
        <TR>
            <TD ALIGN="LEFT"><B>Id</B></TD>
            <TD ALIGN="LEFT">{tid.upper()}</TD>
        </TR>
        <TR>
            <TD ALIGN="LEFT"><B>Name</B></TD>
            <TD ALIGN="LEFT">{tname}</TD>
        </TR>
        <TR>
            <TD ALIGN="LEFT"><B>Target</B></TD>
            <TD ALIGN="LEFT">{pod}</TD>
        </TR>"""
        if probability:
            p_row = f"""
            <TR>
                <TD ALIGN="LEFT"><B>Probability</B></TD>
                <TD ALIGN="LEFT">{probability:.4f}</TD>
            </TR>"""
            formatted_node = f"{formatted_node}\n{p_row}"
        return f"<<TABLE BORDER =\"1\" CELLBORDER=\"1\" CELLSPACING=\"0\">{formatted_node}</TABLE>>"
    
    def _get_viz_consequence(self, node_id, pod, consequence, label=None, probability=None):
        formatted_node = """
        <TR><TD COLSPAN=\"2\" BGCOLOR=\"salmon\"><B>COMPROMISE</B></TD></TR>
        """
        if label:
            label_row = f"<TR><TD COLSPAN=\"2\">{label}</TD></TR>"
            formatted_node = f"{formatted_node}\n{label_row}"
        formatted_node = f"""
        {formatted_node}
        <TR>
            <TD ALIGN="LEFT"><B>Type</B></TD>
            <TD ALIGN="LEFT">{consequence}</TD>
        </TR>
        <TR>
            <TD ALIGN="LEFT"><B>Pod</B></TD>
            <TD ALIGN="LEFT">{pod}</TD>
        </TR>"""
        if probability:
            p_row = f"""
            <TR>
                <TD ALIGN="LEFT"><B>Probability</B></TD>
                <TD ALIGN="LEFT">{probability:.4f}</TD>
            </TR>"""
            formatted_node = f"{formatted_node}\n{p_row}"
        return f"<<TABLE BORDER =\"1\" CELLBORDER=\"1\" CELLSPACING=\"0\">{formatted_node}</TABLE>>"
    
    def _get_viz_vuln(self, node_id, vulid, pod, library, libver, label=None, probability=None):
        formatted_node = """
        <TR><TD COLSPAN=\"2\" BGCOLOR=\"yellow\"><B>VULNERABILITY</B></TD></TR>
        """
        if label:
            label_row = f"<TR><TD COLSPAN=\"2\">{label}</TD></TR>"
            formatted_node = f"{formatted_node}\n{label_row}"
        formatted_node = f"""
        {formatted_node}
        <TR>
            <TD ALIGN="LEFT"><B>CVE Id</B></TD>
            <TD ALIGN="LEFT">{vulid.upper().strip("'")}</TD>
        </TR>
        <TR>
            <TD ALIGN="LEFT"><B>Pod</B></TD>
            <TD ALIGN="LEFT">{pod}</TD>
        </TR>
        <TR>
            <TD ALIGN="LEFT"><B>Library</B></TD>
            <TD ALIGN="LEFT">{library.strip("'")}</TD>
        </TR>
        <TR>
            <TD ALIGN="LEFT"><B>Version</B></TD>
            <TD ALIGN="LEFT">{libver.strip("'")}</TD>
        </TR>"""
        if probability:
            p_row = f"""
            <TR>
                <TD ALIGN="LEFT"><B>Probability</B></TD>
                <TD ALIGN="LEFT">{probability:.4f}</TD>
            </TR>"""
            formatted_node = f"{formatted_node}\n{p_row}"
        return f"<<TABLE BORDER =\"1\" CELLBORDER=\"1\" CELLSPACING=\"0\">{formatted_node}</TABLE>>"
    
    def viz_beautify(self, probability=False, fact_label=True):
        """
        Clean up and the Graphviz representation of the graph

        Args:
            bayesian (bool): whether to display the probability in a bayesian graph is provided.
                the probability must be a property of the graph's nodes
            fact_label: whether to display the label of the MulVAL fact represented by the node.
        """

        logger.info("Beutifying Graphviz Attack Graph")
        def _rec_build(n, prev_n):
            """
            Recursively find the technique nodes and build the ATTACK FLOW Graph
            """
            # Check if the current node is a technique rule derivation
            if "TECHNIQUE" in n[1]["label"]:
                # Extract technique info
                if t_match := re.search(r'\(TECHNIQUE (.*) - (.*)\)', n[1]["label"]):
                    tid = t_match.group(1)
                    tname = t_match.group(2)
                # Extract compromised pod label
                exec_n = list(self.AG.out_edges(n[0]))[0][1]
                exec_n = [n for n in self.AG.nodes.data() if n[0]==exec_n][0]
                if pod := re.search(r'step\((.*)\)', exec_n[1]["label"]):
                    technique_label = exec_n[1]["label"]
                    pod = pod.group(1)
                    if probability and "probability" in exec_n[1]:
                        technique_probability = exec_n[1]["probability"]
                    else:
                        technique_probability = None
                    formatted_label = self._get_viz_technique(
                        node_id = n[0],
                        tid = tid,
                        tname = tname,
                        pod = pod,
                        label = technique_label if fact_label else None,
                        probability = technique_probability)
                    G.add_node(exec_n[0], label=formatted_label, shape="plaintext")
                # If the technique derivation node has more than one parent add an AND node with this node's id
                is_and = False
                if len(self.AG.in_edges(n[0])) > 1:
                    is_and = True
                    G.add_node(n[0], label="AND", shape="circle", style="filled", fillcolor="lightgrey")
                    edges.append((prev_n[0],n[0]))
                    edges.append((n[0],exec_n[0]))
                else:
                    edges.append((prev_n[0], exec_n[0]))
                # Extract attack_step consequences
                for _, cons_n in self.AG.out_edges(exec_n[0]):
                    cons_n = [n for n in self.AG.nodes.data() if n[0]==cons_n][0]
                    if consequence := re.search(r'\(COMPROMISED - (.*)\)' ,cons_n[1]["label"]):
                        consequence = consequence.group(1)
                    cons_id = list(self.AG.out_edges(cons_n[0]))[0][1]
                    # Get the comprimise derived fact label
                    cons_label = self.AG.nodes.data()[cons_id]["label"]
                    if probability and "probability" in self.AG.nodes.data()[cons_id]:
                        cons_probability = self.AG.nodes.data()[cons_id]["probability"]
                    else:
                        cons_probability = None
                    formatted_label = self._get_viz_consequence(
                        node_id = cons_id,
                        pod = pod,
                        consequence = consequence,
                        label = cons_label if fact_label else None,
                        probability = cons_probability)
                    G.add_node(cons_id, label=formatted_label, shape="plaintext")
                    edges.append((exec_n[0],cons_id))
                # Extract exploited vulnerabilities
                for in_n, _ in self.AG.in_edges(n[0]):
                    in_n = [n for n in self.AG.nodes.data() if n[0]==in_n][0]
                    if "vulExists" in in_n[1]["label"]:
                        if vul_id := re.search(r'vulExists\(.*,(.*)\)', in_n[1]["label"]):
                            vul_id = vul_id.group(1)
                            vul_label = in_n[1]["label"]
                            if is_and:
                                edges.append((in_n[0], n[0]))
                            else:
                                edges.append((in_n[0],exec_n[0]))
                            if probability and "probability" in in_n[1]:
                                vul_probability = in_n[1]["probability"]
                            else:
                                vul_probability = None
                        # Get info on the vulnerable library
                        lib_n = list(self.AG.in_edges(in_n[0]))[0][0]
                        lib_n = self.AG.nodes.data()[lib_n]
                        if lib_label := re.search(r'vulExists\((.*),(.*),.*\)', lib_n["label"]):
                            lib_name = lib_label.group(1)
                            lib_ver = lib_label.group(2)
                            formatted_label = self._get_viz_vuln(
                                node_id = in_n[0],
                                vulid = vul_id,
                                pod = pod,
                                library = lib_name,
                                libver = lib_ver,
                                label = vul_label if fact_label else None,
                                probability = vul_probability)
                            G.add_node(in_n[0], label=formatted_label, shape="plaintext")
                # Proceed downstram with the current tech execution node as prev_n
                for _, out_n in self.AG.out_edges(n[0]):
                    out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                    _rec_build(out_n, exec_n)
            elif "COMPROMISED" in n[1]["label"]:
                # Proceed downstream with the derived compromised node as prev_n
                for _, out_n in self.AG.out_edges(n[0]):
                    out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                    _rec_build(out_n, out_n)
            elif "reachable" in n[1]["label"] and len(self.AG.in_edges(n[0]))>1:
                # Consider reachable nodes with multiple parents as OR nodes
                G.add_node(n[0], label="OR", shape="circle", style="filled", fillcolor="lightgrey")
                for in_n, _ in self.AG.in_edges(n[0]):
                    edges.append((in_n, n[0]))
                # Proceed downstream with this node as prev_n
                for _, out_n in self.AG.out_edges(n[0]):
                    out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                    _rec_build(out_n, n)
            else:
                # Proceed downstream with the same prev_n
                for _, out_n in self.AG.out_edges(n[0]):
                    out_n = [n for n in self.AG.nodes.data() if n[0]==out_n][0]
                    _rec_build(out_n, prev_n)
        # Find the 1st node, attackerLocated
        location_node = [n for n in self.AG.nodes.data() if "attackerLocated" in n[1]["label"]][0]
        if location := re.search(r'attackerLocated\((.*)\)', location_node[1]["label"]):
            attacker_label = location_node[1]["label"]
            location = location.group(1)
        # Store the edges to add
        edges = []
        G = nx.DiGraph()    # Initialization of the new graph
        formatted_label = self._get_viz_attacker(
            node_id = location_node[0],
            location = location, 
            label = attacker_label if fact_label else None)
        G.add_node(location_node[0], label=formatted_label, shape="plaintext")
        # Recursively build the new graph starting from attackerLocation
        _rec_build(location_node, location_node)
        # Add the edges to the graph
        G.add_edges_from(edges)
        # Write to file
        if probability:
            dotfile = "BayesianGraph_pretty.dot"
            outfile = "BayesianGraph_pretty.pdf"
        else:
            dotfile = "AttackGraph_pretty.dot"
            outfile = "AttackGraph_pretty.pdf"
        dot_path = os.path.join(self.out_dir, dotfile)
        with open(dot_path, "w") as f:
            nx_agraph.write_dot(G, dot_path)
            p = subprocess.Popen(["dot", "-Tpdf", dotfile, "-o", outfile],
                        cwd=self.out_dir)
            p.wait()
            if os.path.isfile(dot_path):
                os.remove(dot_path)