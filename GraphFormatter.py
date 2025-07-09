import re
import stix2
import os.path
from networkx.drawing import nx_agraph


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

        def _rec_build(n, prev_n, next_nodes):
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