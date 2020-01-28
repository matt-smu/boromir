
METRIC_NAME = None
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
        'metric_summary': METRIC_SUMMARY,
        'cite_key': CITATION_SHORT,
        'citation': CITATION_FULL,
        'metric_usage': USAGE,
    }
    return metadata


class AGBasedSecMet(BaseSecurityMetric):

  def __init__(self):
    super(AGBasedSecMet, self).__init__()
