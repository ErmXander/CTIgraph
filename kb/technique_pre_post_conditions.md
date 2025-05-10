**PRECONDITIONS**<br>
Below are the conditions that must be met in order to apply certain techniques:
- **reachable(pod, proto, port)** <br>
the attacker can, from its location, reach a pod on a given port through a given protocol
- **codeExec(pod)** <br>
the attacker can execute code on the pod
- **fileAccess(pod, perm)** <br>
the attacker has read or write access to files on the pod
- **privilege(pod, level)** <br>
the attacker obtained a certain privilege level
- **credentialAccess(account)** <br>
the attacker obtained the credentials for an account
- **misconfiguration(pod, kind)**
the pod is misconfigured
- **mounts(pod, kind, path)**
the pod has a certain mounted volume
- **imageTrustLevel(pod, trustLevel)**
the pod's image has a given trust level

**POSTCONDITIONS**<br>
Below are the consequences that a technique could result in:
- **compromised(pod, remoteAccess)** <br>
- **compromised(pod, codeExec)** <br>
- **compromisedFile(pod, fileAccess, file, perm)** <br>
- **compromised(pod, dos)** <br>
the attacker could cause Denial of Service to a given pod with an *Impact* technique or by causing dos to one of its dependencies.
- **compromised(pod, persistence)** <br>
the attacker could achieve persistence on a pod through a *Persistence* technique.
- **compromised(pod, dataManipulation)** <br>
the attacker could manipulate data stored.
- **compromisedPrivilege(pod, privEscalation, level)** <br>
the attacker can obtain a certain privilege level through a *Privilege Escalation* technique.
- **credentialAccess(account)** <br>
the attacker can obtain the credentials for an account through a *Credential Access* technique.