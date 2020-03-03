"""Security Metric"""

import os
# import pathlib
import networkx
from networkx.readwrite import json_graph
import json

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


METRIC_NAME = "shortest_path_cumulative"
USAGE = """"""
CITATION_SHORT = 'dacier1996'
CITATION_FULL = """Marc Dacier, Yves Deswarte, and Mohamed Kaâniche. 1996. Quantitative assessment of operational security: Models and tools. Information Systems Security, ed. by SK Katsikas and D. Gritzalis, London, Chapman & Hall (1996), 179–86."""
METRIC_UNIT = "weeks"
METRIC_SUMMARY = """The shortest path is the one which allows to reach the target with the lowest cumulated difficulty.[dacier1996]"""
SCORE_MAP = 'cvss2time'


class shortest_path_metric(AGBasedSecMet):


  def __init__(self) -> None:
    self.METRIC_NAME = METRIC_NAME
    self.METRIC_UNIT = METRIC_UNIT
    self.USAGE = USAGE
    self.CITATION_SHORT = CITATION_SHORT
    self.CITATION_FULL = CITATION_FULL
    self.METRIC_SUMMARY = METRIC_SUMMARY

    super(shortest_path_metric, self).__init__()
  #
  def getMetaData(self):
    metadata = {# The meta data defining the environment
        'cite_key': self.CITATION_SHORT,
        'citation':         self.CITATION_FULL,
        'metric_name': self.METRIC_NAME,
        'usage': self.USAGE,
        'metric_unit': self.METRIC_UNIT,
        'metric_summary': self.METRIC_SUMMARY,
        'attack_graph_name': self.ag.name,
    }
    return metadata

  def calculate(self):

    # @TODO Fix Dependency Handling in Metric Pipelines
    def mttf(A, n=None):
      """Calculates MTTF for a weighted DAG

      MTTF_k = T_k + sum_{L \in out edges}(P_{kL} x MTTF_kL)
                                  | P_kL = lambda_{kL} x T_k
                                  | T_k = 1/ lP_kL = lambda_{kL} x T_kambda_{out rates}

      :param A: attack graph
      :param n: node (start at origin if none)
      :return: MTTF
      """
      metadata = {}

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
      metadata.update({
          'mttf': A.nodes[n]['mttf']
      })

      return A.nodes[n]['mttf'] #, metadata

    self.CheckPreReqs()
    A = self.ag
    A.name = os.path.splitext(FLAGS.input_file)[0]
    if FLAGS.secmet_plot_intermediate_graphs:
      A.plot2(outfilename=A.name + '_001_orig.png')

    A.map_scores = SCORE_MAP

    reduced_ag = A.getReducedGraph()
    mttf(reduced_ag)

    # origin = list(reduced_ag.getOriginnodesByAttackerLocated())[0]
    origin = reduced_ag.origin
    target = list(reduced_ag.getTargetByNoEgressEdges())[0]

    pw_dict = {}
    paths = networkx.all_simple_paths(reduced_ag, origin, target)
    for path in paths:
      mttf_sum = 0
      for n in path:
        mttf_sum += reduced_ag.nodes[n]['mttf']
        print(mttf_sum)
      pw_dict.update({tuple(path): mttf_sum})
      print(pw_dict)
    shortest_path_length = min(pw_dict.values())
    shortest_paths = [key for key in pw_dict if pw_dict[key] == shortest_path_length]
    # shortest_path = networkx.shortest_path(reduced_ag, origin, target, weight='weight')
    # shortest_paths = list(networkx.all_shortest_paths(reduced_ag, origin, target, weight='weight'))
    # shortest_path_length =  networkx.shortest_path_length(reduced_ag, origin, target, weight='weight')



    metadata = self.getMetaData()
    metadata.update({
        # 'attack_graph_original':
  #
  # def CheckPreReqs(self):
  #   passjson.dumps(json_graph.node_link_data(A)),
        # 'attack_graph_reduced': json.dumps(json_graph.node_link_data(tgraph)),
        # 'all_paths_before': json.dumps(shortest_path_before),
        # 'shortest_path': shortest_path,
        'all_shortest_paths': shortest_paths,
        'shortest_path_length': shortest_path_length,
        # 'shortest_path_after': shortest_path_length_after,
        # 'shortest_path_length_after': len(shortest_path_length_after),
        # 'transition_matrix':   json.dumps(tmatrix.todense().tolist()),
    })
    return shortest_path_length, metadata






