import os
import argparse
import stix2

from helper import get_attack_info


def generate_example_cti_bundle(technique_list, kb_path):
    attack_patterns = []
    relationships = []
    vulnerabilities = []
    techniques, _, _, _ = get_attack_info(kb_path)

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

    KB_PATH = os.path.join(os.path.dirname(__file__),"../kb")
    out_dir = os.path.join(os.getcwd(), args.out_dir) if args.out_dir else os.getcwd()
    os.makedirs(out_dir, exist_ok=True)
    out_bundle_path = os.path.join(out_dir, "bundle.json")
    example_techniques = [
        {"id": "T1190", "vulns":["CVE-2025-22870"]}, 
        {"id": "T1498", "vulns": []}
    ]

    bundle = generate_example_cti_bundle(example_techniques, KB_PATH)
    with open(out_bundle_path, "w") as f:
        f.write(bundle.serialize(pretty=True))


if __name__ == "__main__":
    main()