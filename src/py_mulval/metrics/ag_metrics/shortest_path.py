"""Security Metric"""

from py_mulval.metrics.security_metric import AGBasedSecMet

METRIC_NAME = "shortest_path"
USAGE = """"""
CITATION_SHORT = 'dacier1996'
CITATION_FULL = """Marc Dacier, Yves Deswarte, and Mohamed Kaâniche. 1996. Quantitative assessment of operational security: Models and tools. Information Systems Security, ed. by SK Katsikas and D. Gritzalis, London, Chapman & Hall (1996), 179–86."""



class shortest_path_metric(AGBasedSecMet):

  def __init__(self) -> None:
    super(shortest_path_metric, self).__init__()

  def CheckPreReqs(self):
    pass





