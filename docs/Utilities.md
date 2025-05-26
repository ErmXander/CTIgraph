# Utilities
## Build Knowledge Base
The script ```utils/build_kb.py``` can be used to fetch information about the MITRE ATT&CK Techniques, D3FEND Countermeasures and Artifacts from the Digital Artifact Ontology.
```bash
python utils/build_kb.py <output_dir> <opts>
```
#### options:
- **-a, --attack**: download only ATT&CK data.
- **-d, --defend**: download only D3FEND data.
- **-r, --artifacts**: download only Artifacts data.  

The script fill output the relevant data into &lt;output_dir>/kb/ in three different files:
```artifacts.json```, ```attack-techniques.json``` and ```defend-techniques.json```. The script will fetch data using the D3FEND API only if the data already present in the Knowledge Base is from an earlier version of the MITRE Framework.

The file ```kb/attack-techniques.json``` includes an array of ATT&CK techniques defining for each:

- **id**: MITRE ATT&CK identifier of the techique.
- **name**: name of the technique.
- **definition**: description of the technique.
- **countermeasures**: list of D3FEND countermeasures ids that can counter this technique (if any).
- **preconditions**: list of conditions for the applicability of the technique.
- **postconditions**: list of consequences of the successful execution of the technique.

**NOTE**: presently the script cannot generate the mappings between the techniques and their pre/post-conditions.

The file ```kb/defend-techniques.json``` includes an array of D3FEND techniques defining for each:

- **id**: MITRE D3FEND identifier of the technique.
- **name**: name of the technique.

The file ```kb/artifacts.json``` includes an array of digital artifacts defining for each:

- **id**: identifier of the artifact.
- **name**: name of the artifact.
- **da_to_off**: list of identifiers of the related MITRE ATT&CK Techniques.
- **da_to_def**: list of names of the related MITRE D3FEND Techniques.

## Build STIX2.X Bundle
```utils/gen_example_cti.py``` is a simple script that can be used to create an example STIX2.X bundle from a list of techniques and related vulnerabilities. The list and Knowledge Base path can be edited to generate bundles including different techniques.