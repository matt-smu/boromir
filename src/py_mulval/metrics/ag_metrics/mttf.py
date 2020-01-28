"""Security Metric"""

from py_mulval.metrics.security_metric import AGBasedSecMet

METRIC_NAME = "mttf"
METRIC_SUMMARY = """
"""
CITATION_SHORT = 'dacier1996'
CITATION_FULL = """Marc Dacier, Yves Deswarte, and Mohamed Kaâniche. 1996. Quantitative assessment of operational security: Models and tools. Information Systems Security, ed. by SK Katsikas and D. Gritzalis, London, Chapman & Hall (1996), 179–86."""

USAGE = """"""


class mttf_metric(AGBasedSecMet):

  def __init__(self) -> None:
    super(mttf_metric, self).__init__()

  def CheckPreReqs(self):
    pass





