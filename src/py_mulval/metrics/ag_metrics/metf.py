"""Security Metric"""

from py_mulval.metrics.security_metric import AGBasedSecMet

METRIC_NAME = "metf"
METRIC_SUMMARY = """
"""
CITATION_SHORT = 'Ortalo1999'
CITATION_FULL = """Rodolphe Ortalo, Yves Deswarte, and Mohamed Kaâniche. 1999. Experimenting with quantitative evaluation tools for monitoring operational security. IEEE Transactions on Software Engineering 25, 5 (1999), 633–650.
"""
USAGE = """"""


class metf_metric(AGBasedSecMet):

  def __init__(self) -> None:
    super(num_paths_metric, self).__init__()

  #
  # def getMetaData(self):
  #   return super.getMetaData()

  def calculate(self):
    self.CheckPreReqs()

    origin = list(self.ag.getOriginnodesByAttackerLocated())[0]
    target = list(self.ag.getTargetByNoEgressEdges())[0]
    all_paths_before = list(
      networkx.all_simple_paths(self.ag, origin, target))

    nodelist_post_reduce = self.tgraph.getNodeList()
    all_paths_after = list(
      networkx.all_simple_paths(self.tgraph, nodelist_post_reduce[0],
                                nodelist_post_reduce[-1]))
    metadata = self.getMetaData()
    metadata.update({'metric_name': METRIC_NAME, 'metric_unit': METRIC_UNIT,
        'metric_summary':           METRIC_SUMMARY,
        'cite_key':                 CITATION_SHORT, 'citation': CITATION_FULL,
        'metric_usage':             USAGE,
        'all_paths_original':       json.dumps(all_paths_before),
        'all_paths_reduced':        json.dumps(all_paths_after),
        'num_paths_original':       len(all_paths_before),
        'num_paths_reduced':        len(all_paths_after), })
    value = len(all_paths_after)
    return value, metadata





