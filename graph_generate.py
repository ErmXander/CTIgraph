import argparse
import os.path
import CTIgraph

def main():
    desc = "Parse the JSON reprsentation on the Kubernetes infrastructure and" \
        "a STIX2.X bundle containing one or more ATT&CK Techniques to generate MulVAL inputs.\n" \
        "Optionally use those inputs to generate an Attack Graph."
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("infrastructure_path", help="path to the JSON infrastructure representation")
    parser.add_argument("cti_path", help="path to STIX2.x Bundle")
    parser.add_argument("-l", "--location", help="allows to specify the label of a pod in which the attacker is located. By default the attackerLocated(internet)")
    parser.add_argument("-o", "--out", help="specify an output directory")
    parser.add_argument("-g", "--graph", action="store_true", help="generate attack graph from extracted inputs using MulVAL")
    parser.add_argument("-p", "--prune", action="store_true", help="prune the generated attack grap")
    parser.add_argument("-a", "--all", action="store_true", help="keep all MulVAL output files")
    parser.add_argument("-f", "--flow", action="store_true", help="generate ATTACK FLOW representation of the Attack Graph")    
    parser.add_argument("-m", "--mermaid", action="store_true", help="generete a mermaid representation of the Attack Graph")
    args = parser.parse_args()

    out_dir = os.path.join(os.getcwd(), args.out) if args.out else os.getcwd()
    input_extractor = CTIgraph.MulValInputExtractor(
        infrastructure_path=args.infrastructure_path,
        cti_path=args.cti_path,
        output_dir=out_dir,
        location=args.location)
    input_extractor.extract_MulVal_inputs()

    if args.graph:
        facts_path = os.path.join(out_dir, "extracted_facts.P")
        rules_path = os.path.join(out_dir, "extracted_rules.P")
        ag_generator = CTIgraph.AttackGraphGenerator(
            input_facts=facts_path,
            input_rules=rules_path,
            output_dir=out_dir)
        ag_generator.gen_graph(no_prune=not args.prune, cleanup=not args.all, to_flow=args.flow, to_mermaid=args.mermaid)


if __name__ == "__main__":
    main()