# MulVAL Input Extraction
The class ```CTIgraph.MulValInputExtractor``` is responsible for the derivation of MulVAL facts and rules from the representation of the Kubernetes Infrastructure and the CTI.  
MulValInputExtractor is initialized by passing it the path to the infrastructure description, the path to the CTI, the directory in which to save the output facts and rules (*working directory* by default), the attacker's location (*internet* by default) and the path to the Knowledge Base (*./kb* by default).  
MulVAL input extraction is divided into two parts:
the extraction of infrastructure facts and the extraction of techniques facts and rules.
## Extraction of Infrastructure Facts
The method ```extract_infrastructure_inputs()``` parses the JSON file containing the description of the infrastructure which was passed on the initialization of the input extractor. The format of the representation must be compliant with the JSON-schema defined by ```k8infrastructure-schema.json```.  
The method iterates over each pod in described infrastructure extracting relevant facts from their properties; these include:

- **hasLibrary(*pod*, *libName*, *libVer*).**  
 the pod with label *pod* uses the library *libName* which is at version *libVer*.
- **hasArtifact(*libName*, *artID*).**  
 library *libName* is associated to the D3FEND Digital Artifact with ID *artID*.
- **vulExists(*libName*, *libVer*, *cveID*).**  
 library *libName* at version *libVer* is affected by vulnerability *cveID*.
- **dependsOn(*pod*, *dependencyPod*).**  
 the pod with label *pod* is dependent on the services of *dependencyPod*.
- **exposesService(*pod*, *serviceName*, *protocol*, *port*).**  
 the pod with label *pod* exposes the service *serviceName* on port number *port* with protocol *protocol*.
- **hasArtifact(*serviceName*, *artID*).**  
 the service *serviceName* is associated to the D3FEND Digital Artifact with ID *artID*.
- **netRule(*pod*, *target*, *proto*, *port*, *direction*, *action*).**  
 the pod with label *pod* has a network rule specifying that traffic in *Ingress*/*Egress* (determined by *direction*) from/to *target* on port number *port* with protocol *proto* is *allowed*/*denied* (determined by *action*).  
 Depending on what specified in the *type* property of the rule the *target* might be the label of another pod in the infrastructure or *internet*.  
 If *pod* uses a denylist (*enforcement-behavior* == *default-allow*) the fact ```netRule(pod, _, _, _, _, allow).``` is also added.
- **mounts(*pod*, *type*, *path*).**  
 the pod with label *pod* has a mounted volume of type *type* at *path*.
- **hasCountermeasure(*pod*, *d3fendID*).**  
 the pod with label *pod* uses a countermeasure having D3FEND ID *d3fendID*.

## Extraction of Techniques' Facts and Rules
The method ```_parse_cti()``` parses a STIX2.X Bundle; the bundle can contain any SDO, SRO and SCO but should contain at least one SDO of type *attack-pattern* describing an ATT&CK Technique (having an *external-reference* with *source*==*mitre-attack*). The attack-pattern can be linked to zero or more *vulnerability* SDOs via SROs. After parsing the Bundle the method returns a list of Techniques and related targeted Vulnerabilitites in the form:
```python
[
    {'id': tid, 
    'name': technique_name,
    'vulns': [
        cve_id1, 
        cve_id2, 
        ...]
    }, 
    ...
]
```
The method ```extract_technique_inputs()``` uses the returned list of techniques and the information contained in the Knowledge Base to extract relevant facts and derive rules modeling the execution of the techniques.
### Technique Facts
- **techniqueArtifact(*tID*, *artID*).**  
  The technique with ATT&CK ID *tID* is associated with the Digital Ontology Artifact with ID *artID*.
- **techniqueExploits(*tID*, *cveID*).**  
  The technique with ATT&CK ID *tID* exploits the vulnerability *cveID* for its execution.
### Technique Rules
The execution of a technique is modeled through a dynamically generated MulVAL rule; for each technique in the list of techniques the rule ***tID*_attack_step(Pod)** indicating the execution of a the technique with ID *tID* on a podis created. The predicate expressed by the rule is tabled, as required by MulVAL. In order for the derivation of the technique execution to succeed the conditions in the body of the rule must be met; these conditions can be grouped into:

- **Technique Applicability**:  
 Whether a Technique can be applied to a pod given the artifacts associated to the pod and technique and the vulnerabilities present in the pod and exploited by the technique; two different rules are used depending if the technique exploits any vulnerability or not.
    ```prolog
    interaction_rule(
        (podExploitable(P, TID) :-
        podArtifact(P, ArtID),
        techniqueArtifact(TID, ArtID),
        vulExists(P, VulID),
        techniqueExploits(TID, VulID)),
        rule_desc('compatible art+vuln',
        0.0)).

    interaction_rule(
        (podTargetable(P, TID) :-
        podArtifact(P, ArtID),
        techniqueArtifact(TID, ArtID)),
        rule_desc('compatible artifact',
        0.0)).
    ```
- **Absence of Countermeasures**:  
 In order to be able to execute a Technique on a pod it is required that the pod does not use any D3FEND countermeasure that can counter the ATT&CK Technique; for each applicable D3FEND Countermeasure *dID* the negated predicate ```not hasCountermeasure(Pod, dID)``` is added to the Technique execution rule.
- **Presence of Preconditions**:  
 A rule might require the target pod to be in a specific state before being able to be executed on it. The preconditions required by a technique are indicated in the Knowledge Base and include:

    - **reachable(Pod, Proto, Port)**  
        the attacker can reach a pod through a specific protocol and port.
    - **codeExec(Pod)**  
        the attacker can execute code con a pod.
    - **fileAccess(Pod, File, Perm)**  
        the attacker can read/write/execute a file on a pod.
    - **privilege(Pod, Level)**  
        the attacker achieved a given level of privilege over a pod.
    - **credentialAccess(Account)**  
        the attacker managed to access the credentials of an account.
    - **mounts(Pod, Kind, Path)**  
        a pod has a mounted volume of a specific kind at a given path.  

    In the event that the technique *tID* does not specify its preconditions in the Knowledge Base the **unachievable(*tID*)** predicate is added to the body of the rule, preventing the derivation of ***tID*_attack_step(Pod)** for any value of Pod.  

The execution of a technique on a pod compromises the state of that pod; for any kind of compromise produced by technique *tID* a rule with the following form is produced:
```prolog
interaction_rule(
	(comp(Pod) :-
	tID_attack_step(Pod)),
	rule_desc('COMPROMISED - type',
	0.0)).
```
Which indicates that the derivation of the predicate modeling the execution of *tID* on a pod produces in that pod a compromise. The different ways in which a pod can be compromised include:

- **remoteAccess(Pod)**  
    the attacker achieves remote access on a pod.
- **codeExecution(Pod)**
    the attacker can execute code on a pod.
- **fileAccess(Pod, File, Perm)**  
    the attacker can now read/write/execute a file in a pod.
- **dos(Pod)**  
    the attacker caused Denial of Service of a pod.
- **persistence(Pod)**   
    the attacker achieved persistence in a pod.
- **dataManipulation(Pod)**  
    the attacker was able to alter data stored in a pod.
- **privilege(Pod, Level)**  
    the attacker achieved privilege escalation and obtained a given level of privilege
- **credentialAccess(Account)**   
    the attacker obtained access to the credentials for an account.

In addition any technique consequence encountered will be used to define the *attackGoal*s needed by MulVAL for attack Graph generation.

## Additional Facts
The facts extracted from the infrastructure and the techniques are merged. Then meta-facts are added; these specify the attacker starting location (*internet* by default but a pod label could be specified as alternative) and the attack goals extracted by ```extract_technique_inputs()```  based on the possible consequences of the techniques present in the CTI.

## Additional Rules
The rules generated from the techniuqes are appended to a base_ruleset; this ruleset includes the declaration of static predicates (both primitive and derived) and the definition of rules which are needed independently from the techniques that might be encountered in the CTI. Examples of these rules are:

- **Rules modeling the allowed traffic flows**:
    ```prolog
    interaction_rule(
        (allowedFlow(Psrc, Pdst, Protocol, Port) :-
            netRule(Psrc, Pdst, Protocol, Port, egress, allow),
            netRule(Pdst, Psrc, Protocol, Port, ingress, allow),
            not netRule(Psrc, Pdst, Protocol, Port, egress, deny),
            not netRule(Pdst, Psrc, Protocol, Port, ingress, deny)),
        rule_desc('',
        0.0)).

    interaction_rule(
        (allowedFlow(P, internet, Protocol, Port) :-
            netRule(P, internet, Protocol, Port, egress, allow),
            not netRule(P, internet, Protocol, Port, egress, deny)),
        rule_desc('',
        0.0)).

    interaction_rule(
        (allowedFlow(internet, P, Protocol, Port) :-
            netRule(P, internet, Protocol, Port, ingress, allow),
            not netRule(P, internet, Protocol, Port, ingress, deny)),
        rule_desc('',
        0.0)).
    ```
- **Rules modeling the network reachability of a pod**
    ```prolog
    interaction_rule(
        (reachable(P, Protocol, Port) :-
            attackerLocated(Zone),
            allowedFlow(Zone, P, Protocol, Port)),
        rule_desc('directly reachable',
        0.0)).

    interaction_rule(
        (reachable(P, _, _) :-
            attackerLocated(P)),
        rule_desc('attacker in pod',
        0.0)).

    interaction_rule(
        (reachable(P2, Protocol, Port) :-
            codeExec(P1),
            allowedFlow(P1, P2, Protocol, Port)),
        rule_desc('pod reached via multi-hop',
        0.0)).
    ```
- **Rule modeling the spread of DoS to dependent pods**
    ```prolog
    interaction_rule(
        (dos(P) :-
            dos(Dependency),
            dependsOn(P, Dependency)),
        rule_desc('DoS on pod dependency',
        0.0)).
    ```