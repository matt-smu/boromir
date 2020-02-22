from uuid import uuid4

from py_mulval import errors

METRIC_NAME = None
METRIC_UNIT = None
METRIC_SUMMARY = None
CITATION_SHORT = None
CITATION_FULL = None
USAGE = None

class BaseSecurityMetric(object):
  """Object representing a base security metric."""

  def __init__(self):
    super().__init__()

  def CheckPreReqs(self):
    pass

  def getMetaData(self):
    metadata = {  # The meta data defining the environment
        'metric_name': METRIC_NAME,
        'metric_unit': METRIC_UNIT,
        'metric_summary': METRIC_SUMMARY,
        'cite_key': CITATION_SHORT,
        'citation': CITATION_FULL,
        'metric_usage': USAGE,
    }
    return metadata

  def getUnique(self, slice=8):
    return str(uuid.uuid4())[:slice]

  def calculate(self):
    pass


class AGBasedSecMet(BaseSecurityMetric):

  def __init__(self):
    super(AGBasedSecMet, self).__init__()

    self.ag = None
    self.tgraph = None
    self.tmatrix = None

  def CheckPreReqs(self):
    if not self.ag:
      raise errors.Error('AG Metric called without an attack graph set')
    pass

