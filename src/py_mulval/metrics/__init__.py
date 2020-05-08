
"""Import flags."""

from absl import flags
from absl import app

import importlib
import logging
import os
from py_mulval import import_util
from py_mulval import events

FLAGS = flags.FLAGS

flags.DEFINE_boolean('secmet_plot_intermediate_graphs', False, 'Writes graphs to file when true.')

flags.DEFINE_string('secmet_model_size', 'small', 'use exammpe models of this size')
flags.DEFINE_string('secmet_model_type', 'enterprise', 'use exaple models of this type')
## if input_model_name isn't set default to canned models ^
flags.DEFINE_string('input_model_name', None, 'use this mulval model')
flags.DEFINE_string('secmet_fg_path', None, 'path to find fact graphs')
flags.DEFINE_string('secmet_fg_name', None, 'use this fact graph')
flags.DEFINE_string('secmet_fg_dot', None, 'fg dot file path (overrides path/name)')
flags.DEFINE_string('secmet_ag_path', None, 'path to find attack graphs')
flags.DEFINE_string('secmet_ag_name', None, 'use this attack graph')
flags.DEFINE_string('secmet_score_dict', None, 'use this score dictionary')

flags.DEFINE_float('secmet_fix_cvss_score', None, 'Applies this cvss score to all vulnerabilities.')
flags.DEFINE_bool('secmet_random_cvss_score', False, 'Applies random cvss score to all vulnerabilities.')
flags.DEFINE_string('secmet_random_seed', None, 'Use this seed for randoms')
flags.DEFINE_string('secmet_map_scores', None, 'Map AG scores to another domain')
flags.DEFINE_string('secmet_score_strategy', None, 'Apply this weighting and scoring strategy')


AG_METRICS = 'AG_METRICS'
STRUCT_METRICS = 'STRUCT_METRICS'
VALID_METRIC_TYPES = (AG_METRICS, STRUCT_METRICS)

_imported_metrics = set()

def _LoadMetrics():
  return list(import_util.LoadModulesForPath(__path__, __name__))

METRICS = _LoadMetrics()




def LoadMetricFlags(metrics):
  """Imports just the flags module for each provider.

  This allows Boromir to load flag definitions from each provider to include in the
  help text without actually loading any other metric-specific modules.

  Args:
    metrics: series of strings. Each element is a value from VALID_METRICS
        indicating a metric type for which to import the flags module.
  """
  for metric_name in metrics:
    normalized_name = metric_name.lower()
    flags_module_name = '.'.join((__name__, normalized_name, 'flags'))
    importlib.import_module(flags_module_name)


# Import flag definitions for all metric classes.
LoadMetricFlags(VALID_METRIC_TYPES)



def LoadMetricsByType(metric_type, ignore_package_requirements=True):
  """Loads the all modules in the 'metric_name' package.
  Args:
    metric_name: string chosen from VALID_CLOUDS. The name of the provider
        whose modules should be loaded.
    ignore_package_requirements: boolean. If True, the metric's Python package
        requirements file is ignored.
  """
  if metric_type in _imported_metrics:
    return

  # Check package requirements from the provider's pip requirements file.
  normalized_type = metric_type.lower()
  if not ignore_package_requirements:
    requirements.CheckMetricRequirements(normalized_type)

  # Load all modules in the metric_name's directory. Simply loading those modules
  # will cause relevant classes to register
  # themselves so that they can be instantiated during resource provisioning.
  metric_package_path = os.path.join(__path__[0], normalized_type)
  try:
    modules = tuple(import_util.LoadModulesForPath(
        [metric_package_path], __name__ + '.' + normalized_type))
    if not modules:
      raise ImportError('No modules found for metric class %s.' % metric_type)
  except Exception:
    logging.error('Unable to load metric type: %s.', metric_type)
    raise

  # Signal that the provider's modules have been imported.
  _imported_metrics.add(metric_type)
  events.metric_imported.send(metric_type)

for metric_type in VALID_METRIC_TYPES:
  LoadMetricsByType(metric_type)
  # if hasattr(module, 'METRIC_NAME'):
  #   if module.METRIC_NAME in VALID_METRICS:
  #     raise ValueError('There are multiple metrics with METRIC_NAME "%s"' %
  #                      (module.METRIC_NAME))
  #   VALID_METRICS[module.METRIC_NAME] = module