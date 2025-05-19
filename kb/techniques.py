techniques = [
    {
        "id": "t1",
        "name": "technique1",
        "definition": "definition for technique1",
        "tactic": "Execution"
    },
    {
        "id": "t2",
        "name": "technique2",
        "definition": "definition for technique2",
        "tactic": "Execution"
    },
    {
        "id": "t3",
        "name": "technique3",
        "definition": "definition for technique3",
        "tactic": "Execution"
    },
    {
        "id": "t4",
        "name": "technique4",
        "definition": "definition for technique4",
        "tactic": "Persistence"
    },
    {
        "id": "t5",
        "name": "technique5",
        "definition": "definition for technique5",
        "tactic": "Persistence"
    },
    {
        "id": "t6",
        "name": "technique6",
        "definition": "definition for technique6",
        "tactic": "Privilege Escalation"
    },
    {
        "id": "t7",
        "name": "technique7",
        "definition": "definition for technique7",
        "tactic": "Privilege Escalation"
    }, 
    {
        "id": "t8",
        "name": "technique8",
        "definition": "definition for technique8",
        "tactic": "Privilege Escalation"
    },
    {
        "id": "t9",
        "name": "technique9",
        "definition": "definition for technique9",
        "tactic": "Credential Access"
    },
    {
        "id": "t10",
        "name": "technique10",
        "definition": "definition for technique10",
        "tactic": "Credential Access"
    },
    {
        "id": "t13",
        "name": "technique13",
        "definition": "definition for technique13",
        "tactic": "Lateral Movement"
    }, 
    {
        "id": "t14",
        "name": "technique14",
        "definition": "definition for technique14",
        "tactic": "Lateral Movement"
    },
    {
        "id": "t15",
        "name": "technique15",
        "definition": "definition for technique15",
        "tactic": "Collection"
    },
    {
        "id": "t17",
        "name": "technique17",
        "definition": "definition for technique17",
        "tactic": "Impact"
    }, 
        {
        "id": "t18",
        "name": "technique18",
        "definition": "definition for technique18",
        "tactic": "Impact"
    }
]

technique_preconditions = {
    "t1": [{"type": "reachable"}],
    "t2": [{"type": "reachable"},{"type": "privilege", "level": "root"}],
    "t3": [{"type": "reachable"},{"type": "credentialAccess", "account": "admin"}],
    "t4": [{"type": "codeExec"},{"type": "privilege", "level": "root"}],
    "t5": [{"type": "fileAccess", "perm": "write"}],
    "t6": [{"type": "codeExec"}],
    "t7": [{"type": "reachable"},{"type": "credentialAccess", "account": "admin"}],
    "t8": [{"type": "fileAccess", "type": "write"}],
    "t9": [{"type": "fileAccess", "perm": "read"}],
    "t10": [{"type": "codeExec"},{"type": "privilege", "level": "root"}],
    "t13": [{"type": "codeExec"}],
    "t14": [{"type": "codeExec"}, {"type": "mounts", "kind": "hostPath", "path": "*"}],
    "t15": [{"type": "fileAccess", "perm": "read"}],
    "t16": [{"type": "reachable"}],
    "t17": [{"type": "fileAccess", "perm": "write"}],
    "t18": [{"type": "codeExec"}],
}

technique_postconditions = {
    "t1": [{"type": "codeExec"}],
    "t2": [{"type": "codeExec"}],
    "t3": [{"type": "codeExec"}],
    "t4": [{"type": "persistence"}],
    "t5": [{"type": "persistence"}],
    "t6": [{"type": "privEscalation", "level": "root"}],
    "t7": [{"type": "privEscalation", "level": "root"}],
    "t8": [{"type": "privEscalation", "level": "root"}],
    "t9": [{"type": "credentialAccess", "account": "admin"}],
    "t10": [{"type": "credentialAccess", "account": "user"}],
    "t13": [{"type": "remoteAccess"}],
    "t14": [{"type": "remoteAccess"}],
    "t15": [],
    "t17": [{"type": "dataManipulation"}],
    "t18": [{"type": "dos"}]
}

technique_mitigations = {
    "t1": ["d1", "d7"],
    "t2": ["d2"]
}