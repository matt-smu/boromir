
"""Import flags."""

from absl import flags
from absl import app


from py_mulval import import_util


FLAGS = flags.FLAGS


# define secmet global flags here
# flags.DEFINE_string('secmet_ag_path', None, 'use this attack graph')
# flags.DEFINE_boolean('secmet_plot_intermediate_graphs', False, 'Writes graphs to file when true.')
# flags.DEFINE_float('secmet_fix_cvss_score', None, 'Applies this cvss score to all vulnerabilities.')

def _LoadMetrics():
  return list(import_util.LoadModulesForPath(__path__, __name__))

METRICS = _LoadMetrics()

VALID_METRICS = {}
for module in METRICS:
  if module.METRIC_NAME in VALID_METRICS:
    raise ValueError('There are multiple metrics with METRIC_NAME "%s"' %
                     (module.METRIC_NAME))
  VALID_METRICS[module.METRIC_NAME] = module