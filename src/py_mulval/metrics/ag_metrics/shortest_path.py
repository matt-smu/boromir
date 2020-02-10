"""Security Metric"""

import os
import pathlib
import networkx
from networkx.readwrite import json_graph
import json

from py_mulval import configs
from py_mulval import data
from py_mulval import flags
from py_mulval import attack_graph
from py_mulval import mulpy
from py_mulval import py_mulval
from py_mulval import sample
from py_mulval import vm_util
from py_mulval.metrics.security_metric import AGBasedSecMet


FLAGS = flags.FLAGS


METRIC_NAME = "shortest_path"
USAGE = """"""
CITATION_SHORT = 'dacier1996'
CITATION_FULL = """Marc Dacier, Yves Deswarte, and Mohamed Kaâniche. 1996. Quantitative assessment of operational security: Models and tools. Information Systems Security, ed. by SK Katsikas and D. Gritzalis, London, Chapman & Hall (1996), 179–86."""
METRIC_UNIT = "weeks"
METRIC_SUMMARY = """"""""


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

  def CheckPreReqs(self):
    pass

  def calculate(self):
    A = self.ag
    A.name = os.path.splitext(FLAGS.input_file)[0]
    if FLAGS.secmet_plot_intermediate_graphs:
      A.plot2(outfilename=A.name + '_001_orig.png')
    tgraph, tmatrix, nodelist = A.getTransMatrix()

    origin = list(A.getOriginnodesByAttackerLocated())[0]
    target = list(A.getTargetByNoEgressEdges())[0]
    shortest_path_before = list(networkx.all_simple_paths(A, origin, target))
    shortest_path_length_before = min(shortest_path_before, key=len)

    nodelist_post_reduce = tgraph.getNodeList()
    shortest_paths_after = list(
      networkx.all_simple_paths(tgraph, nodelist_post_reduce[0],
                                nodelist_post_reduce[-1]))
    shortest_path_length_after = min(shortest_paths_after, key=len)

    metadata = self.getMetaData()
    metadata.update({
        # 'attack_graph_original':   json.dumps(json_graph.node_link_data(A)),
        # 'attack_graph_reduced': json.dumps(json_graph.node_link_data(tgraph)),
        # 'all_paths_before': json.dumps(shortest_path_before),
        'shortest_path_before': shortest_path_length_before,
        'shortest_path_length_before': len(shortest_path_length_before),
        'all_paths_after': shortest_paths_after,
        'shortest_path_after': shortest_path_length_after,
        'shortest_path_length_after': len(shortest_path_length_after),
        'transition_matrix':   json.dumps(tmatrix.todense().tolist()),
    })
    return len(shortest_path_length_after), metadata






