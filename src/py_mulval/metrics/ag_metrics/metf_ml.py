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
import py_mulval.metrics.security_metric as secmet
FLAGS = flags.FLAGS

METRIC_NAME = "metf_ml"
METRIC_UNIT = "effs"
CITATION_SHORT = 'Ortalo1999'
USAGE = """Accepts an attack graph and the node to start from, or looks for the origin if no node provided"""
METRIC_SUMMARY = """"Determines the survival function complement from reliability engineering."""
CITATION_FULL = """Rodolphe Ortalo, Yves Deswarte, and Mohamed Kaâniche. 1999. Experimenting with quantitative evaluation tools for monitoring operational security. IEEE Transactions on Software Engineering 25, 5 (1999), 633–650.
"""

SCORE_MAP = 'cvss2effort'

class metf_ml_metric(AGBasedSecMet):

  def __init__(self) -> None:
    super(metf_ml_metric, self).__init__()

  def calculate(self):

    def metf(A, n=None):
      """Calculates METF ML for a weighted DAG

      METF_k = T_k + sum_{L \in out edges}(P_{kL} x METF_kL)
                                  | P_kL = lambda_{kL} x T_k
                                  | T_k = 1/ lP_kL = lambda_{kL} x T_kambda_{out rates}

      :param A: attack graph
      :param n: node (start at origin if none)
      :return: METF
      """

      if not n:
        n = A.origin
      if 't_k' not in A.nodes[n].keys():
        scores = A.getOutEdgeValsForKey(n, 'score')  # edge scores should be (mapped) transition rates
        A.nodes[n]['t_k'] = 1 / sum(A.getOutEdgeValsForKey(n, 'score')) if scores else 0
      if 'metf' not in A.nodes[n].keys():
          A.nodes[n]['metf'] = None

      o_edges = [((u, v, k), e) for u, v, k, e in # grab our outbound edges
                 A.out_edges(n, keys=True, data=True)]

      p_sums = 0 # collects (P_{kL} x metf_kL) terms
      for (u, v, k), e in o_edges:
        if 'metf' not in A.nodes[v].keys():
          A.nodes[v]['metf'] = metf(A, v)  # gets target metf from far away
        P = A[u][v][k]['score'] * A.nodes[n]['t_k']  # P_kL = lambda_{kL} x T_k
        p_sums += P * A.nodes[v]['metf']

      A.nodes[n]['metf'] = A.nodes[n]['t_k'] + p_sums # metf for this node
      # metadata.update({
      #     'metf': A.nodes[n]['metf']
      # })

      return A.nodes[n]['metf'] #, metadata

    self.CheckPreReqs()
    A = self.ag

    A.name = os.path.splitext(FLAGS.input_file)[0]
    if FLAGS.secmet_plot_intermediate_graphs:
      A.plot2(outfilename=A.name + '_001_orig.png')

    A.map_scores = SCORE_MAP

    reduced_ag = A.getReducedGraph()

    # origin = list(reduced_ag.getOriginnodesByAttackerLocated())[0]
    origin = reduced_ag.origin
    target = list(reduced_ag.getTargetByNoEgressEdges())[0]


    # reduced_ag.setEdgeScores()
    value = metf(reduced_ag)

    metadata = self.getMetaData()
    # metadata.update(**run_metadata)
    # metadata.update({  # 'attack_graph_original':
    #     #
    #     # def CheckPreReqs(self):
    #     #   passjson.dumps(json_graph.node_link_data(A)),
    #     # 'attack_graph_reduced': json.dumps(json_graph.node_link_data(tgraph)),
    #     # 'all_paths_before': json.dumps(shortest_path_before),
    #     'metf': metf, # 'all_shortest_paths':   shortest_paths,
    #     # 'shortest_path_length': shortest_path_length,
    #     # 'shortest_path_after': shortest_path_length_after,
    #     # 'shortest_path_length_after': len(shortest_path_length_after),
    #     # 'transition_matrix':   json.dumps(tmatrix.todense().tolist()),
    # })
    return value, metadata
