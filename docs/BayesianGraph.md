# Bayesian Graph Generation
The class ```BayesianGraph``` allows the generation of bayesian networks based on a previously generated Attack Graph.  
The class in initialized with the NetworkX representation of the Attack Graph or, alternatively, the graph in .dot format.  
For each type of node the function the probability is computed as follows:

- LEAF nodes: (primitive fact nodes) are assigned a success probability of 1 or, in case of vulnerability nodes, the function ```exp_prob_fn``` is used to compute the probability of successful exploitation.  
```exp_prob_fn``` takes as first argument the CVE_ID of the vulnerability and can accept multiple arguments passed to it via the dict ```exp_fn_args```.
- AND nodes: (rule derivation nodes) a Conditional Probability Table (CPT) is created based on the number of parent nodes using AND logic. In case of a Technique execution node the function ```tech_prob_fn``` is used to computed the probability of successful execution. ```tech_prob_fn``` takes as first argument the ID of the Technique and can accept multiple arguments passed to it via the dict ```tech_fn_args```. The obtained probability is used as base probability in the contruction of the CPT.
- OR nodes: (derived fact nodes) a Conditional Probability Table (CPT) is created based on the number of parent nodes using OR logic.  

The CPT built for each node are assigned to a Pgmpy ```DiscreteBayesianNetwork```. Using Pgmpy's Variable Elimination the marginal probability of each node is computed.  
The method ```print_bayesian_graph``` allows to visualize the Bayesian Graph with Graphviz, showing the node's probability next to its label. 