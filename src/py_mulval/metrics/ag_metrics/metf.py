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
    super(metf_metric, self).__init__()

  def CheckPreReqs(self):
    pass





