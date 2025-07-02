# CTIgraph
CTIgraph is a MulVAL-based tool for the generation of Attack Graphs for Kubernetes infrastrucutres based on Threat Intelligence extracted from STIX2.X Bundles. 

## Tool Pipeline
![image](docs/CTI%20Graph%20Pipeline.png)



## Components
- **MulValInputExtractor**: Parses the JSON representation of the K8s infrastructure and the STIX Bundle to extract MulVAL facts and rules.
- **AttackGraphGenerator**: Uses MulVAL to generate an Attack Graph and post-processes it.
- **GraphFormatter**: Allows to convert a .dot representation of an Attack Graph into AttackFLow-compliant JSON or mermaid's .mmd.
- **DefenseAdvisor**: Provides a suggestion of the defensive techniques to apply to the infrastructure to minimize the attack surface given an Attack Graph.  
## Repository Structure
```
CTIgraph/
├── kb/                     # Default knowledge base with data from MITRE
├── docs/                   # Documentation
├── CTIgraph.py             # Input extraction and graph generation
├── DefenseAdvisor.py       # Countermeasure reccomendations
├── GraphFormatter.py       # Export graph to different formats
├── graph_generate.py       # Graph generation script
├── helper.py               # Helper functions for other modules
├── base_ruleset.P          # Skeleton for extracted MulVAL rules
├── tests/                  # Test cases with their outputs
├── utils/                  # Additional utility scripts
    └──artifact_association # Utilities for llm-based artifact association
├── requirements.txt      
└── README.md             
```

## Current Limitations
 - **Obtaining JSON representation of the infrastrucure**  
 While certain pieces of information can be obtained through automated means by parsing the YAML manifests or using vulnerability scanners such as Trivy some limitations remain.  
 This applies in particular to network policies and the artifacts associated to each library.  
 Regarding the latter under *utils* I have provided an LLM-based associator; this solutions however is limited as well, since the assignments are partial and non-deterministic. Furthermore it may prove costly for large networks.

 - **Visualization of the Attack Graph**  
 Currently the graph can only be visualized through Graphviz and Mermaid. Other format were considered:  
 *Attack Flow* with its Attack Flow Builder does not support the import of any file with a format different than .afb, which can only be obtained through the Attack Flow Builder GUI and not programmatically.  
 *D3FEND CAD* supports the import of STIX, however most of the information that would be included is lost. Only the Techniques and Vulnerabilities SDOs would be preserved, and even then only the Techniques names and ids and the Vulnerabilities ids would be retained.  
 Nevertheless I have included a way to format an Attack Graph to AttackFlow-compliant JSON which would be useful should the Attack Flow Builder be made to accept non-afb formatted files.