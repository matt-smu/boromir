"""Security Metric"""

import pprint

# import pathlib
import networkx

pp = pprint.PrettyPrinter(indent=2)

# from py_mulval import configs
# from py_mulval import data
from py_mulval import flags
# from py_mulval import mulpy
# from py_mulval import py_mulval
# from py_mulval import sample
# from py_mulval import vm_util

from json import JSONEncoder
import numpy

class NumpyArrayEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, numpy.ndarray):
            return obj.tolist()
        return JSONEncoder.default(self, obj)

import numpy as np
from py_mulval.metrics.security_metric import AGBasedSecMet

FLAGS = flags.FLAGS

METRIC_NAME = "nra_amc"
USAGE = """Accepts an attack graph and the node to start from, or looks for  the origin if no node provided"""
CITATION_SHORT = 'Abraham2014'
CITATION_FULL = """Subil Abraham and Suku Nair. 2014. Cyber security analytics: a stochastic model for security quantification using absorbing markov chains. Journal of Communications 9, 12 (2014), 899–907."""
METRIC_UNIT = "list"
METRIC_SUMMARY = """"Node Rank Analysis: The amount of hold time we expect an attacker to incur while trying to advance to the target."""

class nra_amc_metric(AGBasedSecMet):
  """ Simulation of steps taken over the attack graph adjacency matrix, NRA is a count of how many steps were spent at each node in a 2000 count sim.

  original R code
  option_list = list(
    make_option(c("-i", "--input"), type="character", default=NULL,
  	      help="filename of the transition matrix", metavar="character"),
    make_option(c("-o", "--output"), type="character", default=".",
                help="output directory name [default= %default]", metavar="character"),
    make_option(c("-l", "--label"), type="character", default="model_name",
                help="model name", metavar="character"),
    make_option(c("-f", "--format"), type="character", default="png",
                help="output format {png|jpeg|pdf|ps}  [default= %default]", metavar="character")
  );
  """

  def __init__(self) -> None:
    super(nra_amc_metric, self).__init__()
    self.sessions = 2000
    self.steps = np.zeros(self.sessions)


  def getMetaData(self):
    metadata = super().getMetaData()
    return metadata


  def calculate(self):
    """Calculates step counts for each node on a random walk (fundamental matrix)
          :param A: attack graph
          :param n: node (start at origin if none)
          :return: MTTF
          """
    self.CheckPreReqs()

    reduced_ag = self.ag.getReducedGraph()
    self.normalize_scores(reduced_ag, weight='score')
    node_list = list(networkx.topological_sort(reduced_ag))
    # P_scores = networkx.adjacency_matrix(reduced_ag, nodelist=node_list, weight='score')
    # print(P_scores.todense())
    P = networkx.adjacency_matrix(reduced_ag, nodelist=node_list,  weight='weighted_score') # transition matrix P
    # print(P.todense())

    Q = P[:-1,:-1] # Q is the transient states matrix

    I = np.identity(Q.shape[0])
    N = np.linalg.inv(I - Q) # N is fundamental matrix (improved impls available, this follows the paper for perf analysis)


    metadata = self.getMetaData()
    # metadata.update(**run_metadata)
    metadata.update({  # 'attack_graph_original'

        'attack_graph_reduced':reduced_ag.to_dots(),
        'value': N.tolist(),
        'nodelist': node_list,
        # 'transition_matrix':   tmatrix,
        # 'transition_matrix_raw': tmatrix_raw,
    })
    return -1, metadata
