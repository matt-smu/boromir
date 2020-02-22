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


METRIC_NAME = "shortest_path_direct"
CITATION_SHORT = '[ortalo1999]'
USAGE = """"""
METRIC_UNIT = "path length (in effs)"
METRIC_SUMMARY = """the shortest path is obtained by identifying, in the privilege graph, all the direct paths from the attacker node to the target node and evaluating the minimum value of the METF among the values computed for each direct path.[ortalo1999]"""

CITATION_FULL = """Rodolphe Ortalo, Yves Deswarte, and Mohamed Kaâniche. 1999. Experimenting with quantitative evaluation tools for monitoring operational security. IEEE Transactions on Software Engineering 25, 5 (1999), 633–650.
"""


SCORE_MAP = 'cvss2effort'


class shortest_path_direct_metric(AGBasedSecMet):


  def __init__(self) -> None:
    self.METRIC_NAME = METRIC_NAME
    self.METRIC_UNIT = METRIC_UNIT
    self.USAGE = USAGE
    self.CITATION_SHORT = CITATION_SHORT
    self.CITATION_FULL = CITATION_FULL
    self.METRIC_SUMMARY = METRIC_SUMMARY

    super(shortest_path_direct_metric, self).__init__()
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

    shortest_path = networkx.shortest_path(reduced_ag, origin, target, weight='weight')
    shortest_paths = list(networkx.all_shortest_paths(reduced_ag, origin, target, weight='weight'))
    shortest_path_length =  networkx.shortest_path_length(reduced_ag, origin, target, weight='weight')



    metadata = self.getMetaData()
    metadata.update({
        # 'attack_graph_original':
  #
  # def CheckPreReqs(self):
  #   passjson.dumps(json_graph.node_link_data(A)),
        # 'attack_graph_reduced': json.dumps(json_graph.node_link_data(tgraph)),
        # 'all_paths_before': json.dumps(shortest_path_before),
        'shortest_path': shortest_path,
        'all_shortest_paths': shortest_paths,
        'shortest_path_length': shortest_path_length,
        # 'shortest_path_after': shortest_path_length_after,
        # 'shortest_path_length_after': len(shortest_path_length_after),
        # 'transition_matrix':   json.dumps(tmatrix.todense().tolist()),
    })
    return shortest_path_length, metadata






