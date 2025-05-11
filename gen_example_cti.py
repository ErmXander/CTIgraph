import os
import argparse
import stix2

from kb.techniques import techniques


def generate_example_cti_bundle(technique_list):
    attack_patterns = []
    relationships = []
    vulnerabilities = []

    threat_actor = stix2.ThreatActor(
        name = "some threat actor",
        description = "very bad guys"
    )

    for t in technique_list:
        technique = next((tech for tech in techniques if tech["id"] == t["id"]), None)
        if technique is None:
            continue
        attack_pattern = stix2.AttackPattern(
            name = technique["name"],
            description = technique["definition"],
            kill_chain_phases = [
                stix2.KillChainPhase(
                    kill_chain_name = "mitre-attack",
                    phase_name = technique["tactic"])],
            external_references = [
                stix2.ExternalReference(
                    source_name = "mitre-attack",
                    external_id = technique["id"])]
        )
        attack_patterns.append(attack_pattern)
        relationships.append(stix2.Relationship(
            source_ref = threat_actor.id,
            target_ref = attack_pattern.id,
            relationship_type = "uses"
        ))
        if "vulns" in t:
            for v in t["vulns"]:
                vuln = stix2.Vulnerability(
                    name = v,
                    external_references = [
                        stix2.ExternalReference(
                            source_name = "cve",
                            external_id = v)]
                )
                vulnerabilities.append(vuln)
                relationships.append(stix2.Relationship(
                    source_ref = attack_pattern.id,
                    target_ref = vuln.id,
                    relationship_type = "targets"
                ))

    objects = attack_patterns + vulnerabilities + relationships
    objects.insert(0, threat_actor)
    bundle = stix2.Bundle(objects=objects)
    return bundle


def main():
    '''
    Generate a sample STIX2.X Bundle from a list of techniques

    args:
        out_dir: directory in which to save the output bundle
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument("out_dir", help="path to the directory in which to save the output file")
    args = parser.parse_args()

    out_dir = os.path.join(os.getcwd(), args.out_dir) if args.out_dir else os.getcwd()
    os.makedirs(out_dir, exist_ok=True)
    out_bundle_path = os.path.join(out_dir, "example_bundle.json")
    example_techniques = [
        {"id": "t1", "vulns":["vul1"]}, 
        {"id": "t2"}, 
        {"id": "t3"}, 
        {"id": "t14"}, 
        {"id": "t15"}, 
        {"id": "t18"}, 
        {"id": "t6"}
    ]

    bundle = generate_example_cti_bundle(example_techniques)
    with open(out_bundle_path, "w") as f:
        f.write(bundle.serialize(pretty=True))


if __name__ == "__main__":
    main()