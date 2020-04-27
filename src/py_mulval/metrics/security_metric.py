from uuid import uuid4
import sys
from py_mulval import errors
from py_mulval import flag_util

# These module vars should describe the metric and get included in the metadata
METRIC_NAME = None  # required for benchmark naming, should be unique
METRIC_UNIT = None
METRIC_SUMMARY = None
CITATION_SHORT = None
CITATION_FULL = None
USAGE = None


class BaseSecurityMetric(object):
  """Object representing a base security metric."""

  def __init__(self) -> None: # https://refactoring.guru/design-patterns/builder/python/example
    # Set instance properties to whatever they are down there
    current_module = sys.modules[self.__class__.__module__]
    self.METRIC_NAME = current_module.METRIC_NAME
    self.METRIC_UNIT = current_module.METRIC_UNIT
    self.USAGE = current_module.USAGE
    self.CITATION_SHORT = current_module.CITATION_SHORT
    self.CITATION_FULL = current_module.CITATION_FULL
    self.METRIC_SUMMARY = current_module.METRIC_SUMMARY

    super().__init__()

  def CheckPreReqs(self):
    pass

  def getMetaData(self):
    metadata = {  # The meta data defining the environment
        'metric_name': self.METRIC_NAME,
        'metric_unit': self.METRIC_UNIT,
        'metric_summary': self.METRIC_SUMMARY,
        'cite_key': self.CITATION_SHORT,
        'citation': self.CITATION_FULL,
        'metric_usage': self.USAGE,
    }
    flags_sent = flag_util.GetProvidedCommandLineFlags()
    metadata.update(flags_sent)
    return metadata

  def getUnique(self, slice=8):
    """ Gets a unique value for suffixes and such. @TODO seed this properly
    :param slice: The bits off the end of UUID4 needed
    :return: unique value
    """
    rd = random.Random()
    rd.seed(0)
    uuid.uuid4 = lambda: uuid.UUID(int=rd.getrandbits(128))
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

