# Artifact Association

The association of each of the pods' libraries to MITRE's DAO artifacts is one of the main limiting factors for obtaining a JSON representation of the K8s infrastructure. To automate the association process an LLM-based approach was attempted:

## LLM-Based Association
The class ```LLM_Associator``` in ```utils/artifact_association/artifact_association.py``` is responsible for mapping each library to the artifacts.  
The class includes methods to create a *vector_store* and upload a JSON file listing the D3FEND artifacts (id and definition of each artifact).  
The method  ```get_llm_response``` uses OpenAI's Responses API to obtain the library mappings  
```gpt-4o-mini``` is used as model.  
The model can access the vector_store which includes the artifacts knowledge base using a ```file_search``` tool.  
Additionally, it can search the internet to find information about the library using the ```web_search_preview``` tool.  
In order to make the association as deterministic as possible the ```temperature``` was set to 0.  
The following was given as prompt to the model:  
```python
    f"""
        Given the library {lib_name}, use your knowledge of MITRE's Digital Artifact Ontology to map the library to the appropriate artifacts.
    """
```
Where ```lib_name``` is the name to map to the artifacts.  
The following system message was provided:
```python
    f"""
            You are a cybersecurity analyst with extensive knowledge of MITRE's Digital Artifact Ontology.
            Limit your web search only to the official websites of the libraries and Github.
            Associate as many artifacts as you think appropriate.
            The output must include only the JSON following the example: {json.dumps(example_json)}.
        """
```
Where the example JSON is:
```python
    example_json = {
            "artifacts": [
                {"id": "artifact1"},
                {"id": "artifact2"},
                {"id": "artifact3"}
            ]}
```
The response from the LLM is then post-processed to obtain only the mappings in JSON format.

## Usage Example
The way the ```LLM_associator``` is intended to be used is by first using Trivy to obtain the libraries used by each pod; then each library is passed to the ```LLM_associator``` in order to obtain its artifacts mappings.

## Limitations
- Only few artifacts are assigned to each library even when additional ones should also be included.
- The associations are non-deterministic. The artifacts and number of artifacts associated to the same library change between calls (at least in part).
- It might be expensive to obtain the associations for each library of each pod.