# CTIgraph
CTIgraph is a MulVAL-based tool for the generation of Attack Graphs for Kubernetes infrastrucutres based on Threat Intelligence extracted from STIX2.X Bundles.  
## Components
- **MulValInputExtractor**: Parses the JSON representation of the K8s infrastructure and the STIX Bundle to extract MulVAL facts and rules.
- **AttackGraphGenerator**: Uses MulVAL to generate an Attack Graph and post-processes it.
- **GraphFormatter**: Allows to convert a .dot representation of an Attack Graph into AttackFLow-compliant JSON or mermaid's .mmd.
- **DefenseAdvisor**: Provides a suggestion of the defensive techniques to apply to the infrastructure to minimize the attack surface given an Attack Graph.  
## Repository Structure
```
CTIgraph/
├── kb/                   # Default knowledge base with data from MITRE
├── docs/                 # Documentation
├── CTIgraph.py           # Input extraction and graph generation
├── DefenseAdvisor.py     # Countermeasure reccomendations
├── GraphFormatter.py     # Export graph to different formats
├── graph_generate.py     # Graph generation script
├── helper.py             # Helper functions for other modules
├── base_ruleset.P        # Skeleton for extracted MulVAL rules
├── tests/                # Test cases with their outputs
├── utils/                # Additional utility scripts
├── requirements.txt      
└── README.md             
```