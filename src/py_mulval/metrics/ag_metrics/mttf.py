"""Security Metric"""

import os
# import pathlib
import networkx
from networkx.readwrite import json_graph
import json

import pprint

pp = pprint.PrettyPrinter(indent=2)

# from py_mulval import configs
# from py_mulval import data
from py_mulval import flags
from py_mulval import attack_graph
# from py_mulval import mulpy
# from py_mulval import py_mulval
# from py_mulval import sample
# from py_mulval import vm_util
from py_mulval.metrics.security_metric import AGBasedSecMet

FLAGS = flags.FLAGS

METRIC_NAME = "mttf"
USAGE = """Accepts an attack graph and the node to start from, or looks for 
the origin if no node provided"""
CITATION_SHORT = 'dacier1996'
CITATION_FULL = """Marc Dacier, Yves Deswarte, and Mohamed Kaâniche. 1996. 
Quantitative assessment of operational security: Models and tools. 
Information Systems Security, ed. by SK Katsikas and D. Gritzalis, London, 
Chapman & Hall (1996), 179–86."""
METRIC_UNIT = "weeks"
METRIC_SUMMARY = """"Mean Time To Failure: Determines the survival function complement from reliability engineering."""

# SCORE_MAP = 'cvss2time'


class mttf_metric(AGBasedSecMet):

  def __init__(self) -> None:

    super(mttf_metric, self).__init__()

  def getMetaData(self):
    metadata = super().getMetaData()

    return metadata


  def calculate(self):

    def mttf(A, n=None):
      """Calculates MTTF for a weighted DAG

      MTTF_k = T_k + sum_{L \in out edges}(P_{kL} x MTTF_kL)
                                  | P_kL = lambda_{kL} x T_k
                                  | T_k = 1/ lP_kL = lambda_{kL} x T_kambda_{out rates}

      :param A: attack graph
      :param n: node (start at origin if none)
      :return: MTTF
      """

      # init if not done already
      # for n in A.nodes():
      if not n:
        n = A.origin
      if 't_k' not in A.nodes[n].keys():
        scores = A.getOutEdgeValsForKey(n, 'score')  # edge scores should be (mapped) transition rates
        A.nodes[n]['t_k'] = 1 / sum(A.getOutEdgeValsForKey(n, 'score')) if scores else 0
      if 'mttf' not in A.nodes[n].keys():
          A.nodes[n]['mttf'] = None

      o_edges = [((u, v, k), e) for u, v, k, e in # grab our outbound edges
                 A.out_edges(n, keys=True, data=True)]

      p_sums = 0 # collects (P_{kL} x MTTF_kL) terms
      for (u, v, k), e in o_edges:
        if 'mttf' not in A.nodes[v].keys():
          A.nodes[v]['mttf'] = mttf(A, v)  # gets target mttf from far away
        P = A[u][v][k]['score'] * A.nodes[n]['t_k']  # P_kL = lambda_{kL} x T_k
        p_sums += P * A.nodes[v]['mttf']

      A.nodes[n]['mttf'] = A.nodes[n]['t_k'] + p_sums # mttf for this node

      return A.nodes[n]['mttf']

    self.CheckPreReqs()
    A = self.ag
    print('-----', A.name)
    # A.name = os.path.splitext(FLAGS.input_file)[0]
    if FLAGS.secmet_plot_intermediate_graphs:
      A.plot2(outfilename=A.name + '_001_orig.png')

    # A.map_scores = SCORE_MAP

    reduced_ag = A.getReducedGraph()

    # origin = list(reduced_ag.getOriginnodesByAttackerLocated())[0]
    origin = reduced_ag.origin
    target = list(reduced_ag.getTargetByNoEgressEdges())[0]


    # reduced_ag.setEdgeScores()
    mttf = mttf(reduced_ag)

    print(reduced_ag.edges(data=True))
    print(networkx.adjacency_matrix(reduced_ag, weight='score_orig'))
    tmatrix = json.dumps(networkx.adjacency_matrix(reduced_ag, weight='score').todense().tolist())
    tmatrix_raw = json.dumps(networkx.adjacency_matrix(reduced_ag, weight='score_orig').todense().tolist())

    metadata = self.getMetaData()
    # metadata.update(**run_metadata)
    metadata.update({  # 'attack_graph_original':
        #
        # def CheckPreReqs(self):
        #   passjson.dumps(json_graph.node_link_data(A)),
        # 'attack_graph_reduced': json.dumps(json_graph.node_link_data(reduced_ag)),
        'attack_graph_reduced':reduced_ag.to_dots(),
        # 'all_paths_before': json.dumps(shortest_path_before),
        'mttf': mttf, # 'all_shortest_paths':   shortest_paths,
        # 'shortest_path_length': shortest_path_length,
        # 'shortest_path_after': shortest_path_length_after,
        # 'shortest_path_length_after': len(shortest_path_length_after),
        'transition_matrix':   tmatrix,
        'transition_matrix_raw': tmatrix_raw,
    })
    return mttf, metadata
