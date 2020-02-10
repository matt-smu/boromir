
"""Import flags."""

from absl import flags
from absl import app


from py_mulval import import_util

FLAGS = flags.FLAGS

# def _LoadMetrics():
#   return list(import_util.LoadModulesForPath(__path__, __name__))
#
# METRICS = _LoadMetrics()
#
# VALID_METRICS = {}
# for module in METRICS:
#   if module. and  module.METRIC_NAME  in VALID_METRICS:
#     raise ValueError('There are multiple metrics with METRIC_NAME "%s"' %
#                      (module.METRIC_NAME))
#   VALID_METRICS[module.METRIC_NAME] = module