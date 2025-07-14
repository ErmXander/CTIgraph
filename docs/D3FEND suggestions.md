# Countermeasure Suggestions
![image](./defense-advisor-flow.svg)
The class ```DefenseAdvisor``` is responsible for the suggestion of D3FEND Techniques to counter the ATT&CK Techniques in an Attack Graph with the aim of minimizing the attack surface of the infrastructure.  
DefenseAdvisor is initialized by passing it the path to the description of the Kubernetes Infrastructure, the path to the Knowledge Base (*./kb* by default) and the output directory (*working directory* by default).  
The method  ```getCountermeasures()``` takes an Attack Graph (NetworkX Graph) as input and traverses it recursively starting from its root (*attackerLocated* node). Whenever a Technique attack_step node is found the method will check if the node is still reachable: a technique node is reachable if each of the nodes used for the Technique's rule derivation are reachable (in_degree > 0).

- If the Technique attack_step is **no longer reachable** any countermeasure that might have been identified for the node during a previous visit is popped and the node is removed.
- If the Technique attack_step is **still reachable** the methods identifies any applicable D3FEND Technique for the pod (for which the pod shares at least one artifact with the defensive technique) that can counter the ATT&CK Technique. If at least one countermeasure is found the attack_step node is removed.

It is possible to define some restrictions for the defensive analysis:

- **excluded_pods**  
    a list of labels that allows to specify one or more pods to ignore during the analysis.
- **excluded_countermeasures**  
    a list of D3FEND IDs that allows to specify one or more D3FEND Techniques to not consider during the analysis.
- **exclusion_map**
    a dictionary specifying for one or more pods a list of D3FEND Techniques that should not be applied to the pod.