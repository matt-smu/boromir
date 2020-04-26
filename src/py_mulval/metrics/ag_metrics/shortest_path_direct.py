"""Security Metric"""

import os
# import pathlib
import networkx
from networkx.readwrite import json_graph
import json

from py_mulval import flags
from py_mulval import attack_graph
from py_mulval.metrics.security_metric import AGBasedSecMet


FLAGS = flags.FLAGS


METRIC_NAME = "shortest_path_direct"
CITATION_SHORT = '[ortalo1999]'
USAGE = """"""
METRIC_UNIT = "path length (in effs)"
METRIC_SUMMARY = """the shortest path is obtained by identifying, in the privilege graph, all the direct paths from the attacker node to the target node and evaluating the minimum value of the METF among the values computed for each direct path.[ortalo1999]"""

CITATION_FULL = """Rodolphe Ortalo, Yves Deswarte, and Mohamed Kaâniche. 1999. Experimenting with quantitative evaluation tools for monitoring operational security. IEEE Transactions on Software Engineering 25, 5 (1999), 633–650.
"""


# SCORE_MAP = 'cvss2effort'
SCORE_MAP = 'cvss2time'

class shortest_path_direct_metric(AGBasedSecMet):


  def __init__(self) -> None:
    super(shortest_path_direct_metric, self).__init__()


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

    pw_dict = {}
    paths = networkx.all_simple_paths(reduced_ag, origin, target)
    for spath in paths:
      for path in map(networkx.utils.pairwise, [spath]):
        min_edge = {} # holds min {(u,v): weight} for each multi-edge pair
        for pair in path:
          pair_edges = reduced_ag.get_edge_data(pair[0], pair[1])
          for k in pair_edges.keys():
            if (pair[0], pair[1]) not in min_edge.keys() or min_edge[(pair[0], pair[1])] > pair_edges[k]['weight']:
              min_edge[(pair[0], pair[1])] = pair_edges[k]['weight']
      pw_dict[tuple(path)] = sum(min_edge.values())
    shortest_path_length = min(pw_dict.values())
    shortest_paths = [key for key in pw_dict if pw_dict[key] == shortest_path_length]


    metadata = self.getMetaData()
    metadata.update({
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






