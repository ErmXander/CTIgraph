import os
import subprocess
import re
import numpy as np
import random
from itertools import product
import requests
import networkx as nx
from networkx.drawing import nx_agraph
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination
import time

from helper import decycle, prune_graph, get_logger
from GraphFormatter import AGFormatter
logger = get_logger(__name__)


def random_exploitability(vulID):
    """
    Random exploitation probability
    """
    return random.uniform(0, 1)

def get_epss(vulID, default_value=1):
    """"
    Fetch the epss for a vulnerability
    
    Args:
        vulID (string): CVE ID of the vulnerability
        default_value (float): value to use if cannot retrieve epss for a vulnerability
    Returns:
        epss (float): epss of the vulnerability if available otherwise the default value
    """
    API_URL =  "https://api.first.org/data/v1/epss?cve="
    try:
        r = requests.get(f"{API_URL}{vulID}")
        r.raise_for_status()
        response = r.json()
        data = response["data"][0]
        if data:
            epss = float(data["epss"])
            logger.debug(f"Fetched epss={epss} for {vulID}")
            return epss
        else:
            logger.debug(f"Assigning default epss value={default_value} to {vulID}")
            return float(default_value) if 0<=default_value<=1 else 1
    except requests.exceptions.HTTPError as e:
        logger.error(f"Error fetching epss of {vulID}: {e}")
        logger.debug(f"Assigning default epss value={default_value} to {vulID}")
        return float(default_value) if 0<=default_value<=1 else 1


class BayesianGraph:

    def __init__(self, AttackGraph=None, dot_path=None, exp_prob_fn=random_exploitability, exp_fn_args={}, tech_prob_fn=None, tech_fn_args={}):
        """
        Initializes the Bayesian Graph

        Args:
            AttackGraph: NetworkX graph representing the Attack Graph
            dot_path: path to the .dot file describing the Attack Graph
            exp_prob_fn: function to compute the exploitation probability of vulnerabilities
            exp_fn_args: dict with the arguments to pass to the exploitation probability function
            tech_prob_fn: function to compute the technique execution probability
            tech_fn_args: dict with the arguments to pass to the technique probability function
        """

        # Read the graph from .dot file if not provided
        if AttackGraph:
            AttackGraph = AttackGraph
        elif dot_path is not None:
            AttackGraph = nx_agraph.read_dot(dot_path)
        else:
            raise Exception("Cannot initialize the Bayesian Graph:\n" \
            "No AttackGraph was provided")
        
        self.AG = nx.DiGraph(AttackGraph)
        self.exp_prob_fn = exp_prob_fn
        self.tech_prob_fn = tech_prob_fn
        self.exp_fn_args = exp_fn_args
        self.tech_fn_args = tech_fn_args

        logger.info("Beginning Bayesian Graph generation")
        start_time = time.time()

        prune_graph(self.AG)
        decycle(self.AG)

        # Init the Bayesian Network
        self.model = DiscreteBayesianNetwork(self.AG.edges())

        for n in self.AG.nodes(data=True):
            # Build and add the CPT of the node
            cpt = self._build_node_cpt(n)
            self.model.add_cpds(cpt)
        
        # Check correctness
        if not self.model.check_model():
            raise ValueError(f"Error during Bayesian Network creation")

        # Let Pgmpy compute the probabilities of each node
        infer = VariableElimination(self.model)
        for n in self.AG.nodes(data=True):
            probability = infer.query([n[0]]).values[1]
            n[1]["probability"] = probability
            n[1]["label"] = f"{n[1]['label']}\np:{probability:.4f}"

        elapsed_time = time.time() - start_time
        logger.info(f"Bayesian Graph generation completed in {elapsed_time} seconds")



    def _get_node_type(self, node):
        """
        Assigns a node type (OR, AND, LEAF) to the node.

        Args:
            node: A dict representing a node in the Attack Graph
        """

        # A rule derivation node is always an AND node,
        # A primitive fact node is a LEAF node,
        # A derived fact node is an OR node.
        label = node[1]["label"]
        if match := re.search(r':RULE ', label):
            return "AND"
        elif self.AG.in_degree(node[0]) == 0:
            return "LEAF"
        else:
            return "OR"


    def _build_node_cpt(self, node):
        """
        Builds a Conditional Probability Table for the node

        Args:
            node: A dict representing a node in the Attack Graph

        Returns:
            the CPT of the node
        """

        # Get the node type (AND, OR, LEAF) for the node
        node_type = self._get_node_type(node)

        # In case of LEAF node: 
        # for Vulnerability nodes: assign the probabilities obtained with the probability function
        # for other primitive facts: assign 1 as probability
        if node_type == "LEAF":
            if match := re.search(r'vulExists\(.*,(.*)\)', node[1]["label"]):
                vulID = match.group(1)
                p = float(self.exp_prob_fn(vulID.strip("'"), **self.exp_fn_args))
            else:
                p = float(1)
            cpd = TabularCPD(
                variable=node[0],
                variable_card=2,
                values=[[1-p],[p]])
            return cpd
        # Build the AND/OR cpd based on the parent nodes
        parents = [in_n for in_n, _ in self.AG.in_edges(node[0])]
        n_parents = len(parents)

        # Get all combinations of parent states (0 or 1)
        parent_states = list(product([0,1], repeat=n_parents))
        base_prob = 1
        # Get the node state values for each combination of parents'states given AND/OR logic
        if node_type == "AND":
            node_values = [self._and_logic(state) for state in parent_states]
            # In case of Technique Execution Nodes consider the execution probability
            if match := re.search(r'\(TECHNIQUE (.*) - (.*)\)', node[1]["label"]):
                tid = match.group(1)
                if self.tech_prob_fn is not None:
                    base_prob = self.tech_prob_fn(tid, **self.tech_fn_args)
        elif node_type == "OR":
            node_values = [self._or_logic(state) for state in parent_states]
        
        # Build the table for the node
        cpt_0 = []  # P(node==0)
        cpt_1 = []  # P(node==1)
        for val in node_values:
            if val == 0:
                cpt_0.append(1)
                cpt_1.append(0)
            else:
                cpt_0.append(1-base_prob)
                cpt_1.append(base_prob)
        # Table with:
        # Rows: Probability of node=1, Probability of node=2
        # Columns: States of the parents
        cpt_values = np.array([cpt_0, cpt_1])
        cpd = TabularCPD(
            variable=node[0],
            variable_card=2,
            values=cpt_values,
            evidence=parents,
            evidence_card=[2]*n_parents)
        return cpd


    # Helper functions to model AND/OR logic from parents' states
    def _or_logic(self, states):
        return int(any(states))
    def _and_logic(self, states):
        return int(all(states))


    def print_bayesian_graph(self, out_dir, beautify=False, keeplabel=False):
        out_path = os.path.join(out_dir, "BayesianGraph.dot")
        nx_agraph.write_dot(self.AG, out_path)
        p = subprocess.Popen(["dot", "-Tpdf", "BayesianGraph.dot", "-o", "BayesianGraph.pdf"],
                    cwd=out_dir)
        p.wait()
        if beautify:
            formatter = AGFormatter(out_dir, self.AG)
            formatter.viz_beautify(probability=True, fact_label=keeplabel)

