# Copyright 2014 PerfKitBenchmarker Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Metric set specific functions and definitions."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import collections
import copy
import itertools


from py_mulval import configs
from py_mulval import flags
from py_mulval import secmet_benchmarks
import six
from six.moves import zip

FLAGS = flags.FLAGS

flags.DEFINE_string('flag_matrix', None,
                    'The name of the flag matrix to run.')
flags.DEFINE_string('flag_zip', None,
                    'The name of the flag zip to run.')
flags.DEFINE_integer('num_benchmark_copies', 1,
                     'The number of copies of each benchmark config to run.')


MESSAGE = 'message'

BENCHMARK_LIST = 'benchmark_list'

STANDARD_SET = 'standard_set'

BENCHMARK_SETS = {
    STANDARD_SET: {
        MESSAGE: ('The standard_set is a community agreed upon set of '
                  'benchmarks to measure security performance.'),
        BENCHMARK_LIST: [
            'num_paths',
            # 'avg_path_length',
            'shortest_path_direct',
            'shortest_path_cumulative',
            'nra_amc',
            'probpath',
            'epl',
            'epl_unnorm',
            # 'mttr',
            'mttf',
            'metf_ml',
            'metf_tm',

        ]
    },
    'ag_based_metric_set': {
        MESSAGE: 'Attack Graph Based Metrics Set.',
        BENCHMARK_LIST: ['num_paths',]
    }, 'structural_metric_set': {MESSAGE: 'Structural Metric Set.',
        BENCHMARK_LIST:                   [STANDARD_SET]},
}


class FlagMatrixNotFoundException(Exception):
  pass


class FlagZipNotFoundException(Exception):
  pass


def _GetValidBenchmarks():
  """Returns a dict mapping valid benchmark names to their modules."""
  # if FLAGS.os_type in os_types.WINDOWS_OS_TYPES:
  #   return windows_benchmarks.VALID_BENCHMARKS
  # return linux_benchmarks.VALID_BENCHMARKS
  return secmet_benchmarks.VALID_BENCHMARKS


def _GetValidPackages():
  """Returns a dict mapping valid package names to their modules."""
  # if FLAGS.os_type in os_types.WINDOWS_OS_TYPES:
  #   return windows_packages.PACKAGES
  # return linux_packages.PACKAGES
  return secmet_packages.PACKAGES


def BenchmarkModule(benchmark_name):
  """Finds the module for a benchmark by name.

  Args:
    benchmark_name: The name of the benchmark.

  Returns:
    The benchmark's module, or None if the benchmark is invalid.
  """
  valid_benchmarks = _GetValidBenchmarks()
  return valid_benchmarks.get(benchmark_name)


def PackageModule(package_name):
  """Finds the module for a package by name.

  Args:
    package_name: The name of the package.

  Returns:
    The package's module, or None if the package_name is invalid.
  """
  packages = _GetValidPackages()
  return packages.get(package_name)


def _GetBenchmarksFromUserConfig(user_config):
  """Returns a list of benchmark module, config tuples."""
  benchmarks = user_config.get('benchmarks', [])
  valid_benchmarks = _GetValidBenchmarks()
  benchmark_config_list = []

  for entry in benchmarks:
    name, user_config = entry.popitem()
    try:
      benchmark_module = valid_benchmarks[name]
    except KeyError:
      raise ValueError('Benchmark "%s" not valid on os_type "%s"' %
                       (name, FLAGS.os_type))
    benchmark_config_list.append((benchmark_module, user_config))

  return benchmark_config_list


def _GetConfigForAxis(benchmark_config, flag_config):
  config = copy.copy(benchmark_config)
  config_local_flags = config.get('flags', {})
  config['flags'] = copy.deepcopy(configs.GetConfigFlags())
  config['flags'].update(config_local_flags)
  for setting in flag_config:
    config['flags'].update(setting)
  return config


def _AssertZipAxesHaveSameLength(axes):
  expected_length = len(axes[0])
  for axis in axes[1:]:
    if len(axis) != expected_length:
      raise ValueError('flag_zip axes must all be the same length')


def _AssertFlagMatrixAndZipDefsExist(benchmark_config,
                                     flag_matrix_name,
                                     flag_zip_name):
  """Asserts that specified flag_matrix and flag_zip exist.

  Both flag_matrix_name and flag_zip_name can be None, meaning that the user
  (or the benchmark_config) did not specify them.
from py_mulval import flags
  Args:
    benchmark_config: benchmark_config
    flag_matrix_name: name of the flag_matrix_def specified by the user via a
      flag, specified in the benchmark_config, or None.
    flag_zip_name: name of the flag_zip_def specified by the user via a flag,
      specified in the benchmark_config, or None.

  Raises:
    FlagMatrixNotFoundException: if flag_matrix_name is not None, and is not
      found in the flag_matrix_defs section of the benchmark_config.
    FlagZipNotFoundException: if flag_zip_name is not None, and is not
      found in the flag_zip_defs section of the benchmark_config.
  """
  if (flag_matrix_name and
      flag_matrix_name not in
      benchmark_config.get('flag_matrix_defs', {})):
    raise FlagMatrixNotFoundException('No flag_matrix with name {0}'
                                      .format(flag_matrix_name))
  if (flag_zip_name and
      flag_zip_name not in
      benchmark_config.get('flag_zip_defs', {})):
    raise FlagZipNotFoundException('No flag_zip with name {0}'
                                   .format(flag_zip_name))


def GetBenchmarksFromFlags():
  """Returns a list of benchmarks to run based on the benchmarks flag.

  If no benchmarks (or sets) are specified, this will return the standard set.
  If multiple sets or mixes of sets and benchmarks are specified, this will
  return the union of all sets and individual benchmarks.

  Raises:
    ValueError: when benchmark_name is not valid for os_type supplied
  """
  user_config = configs.GetUserConfig()
  benchmark_config_list = _GetBenchmarksFromUserConfig(user_config)
  if benchmark_config_list and not FLAGS['benchmarks'].present:
    return benchmark_config_list

  benchmark_queue = collections.deque(FLAGS.benchmarks)
  benchmark_names = []
  benchmark_set = set()

  while benchmark_queue:
    benchmark = benchmark_queue.popleft()
    if benchmark in benchmark_set:
      continue
    benchmark_set.add(benchmark)
    if benchmark in BENCHMARK_SETS:
      benchmark_queue.extendleft(BENCHMARK_SETS[benchmark][BENCHMARK_LIST])
    else:
      benchmark_names.append(benchmark)

  valid_benchmarks = _GetValidBenchmarks()

  # create a list of module, config tuples to return
  benchmark_config_list = []
  for benchmark_name in benchmark_names:
    benchmark_config = user_config.get(benchmark_name, {})
    benchmark_name = benchmark_config.get('name', benchmark_name)
    benchmark_module = valid_benchmarks.get(benchmark_name)

    if benchmark_module is None:
      raise ValueError('Benchmark "%s" not valid on os_type "%s"' %
                       (benchmark_name, FLAGS.os_type))

    flag_matrix_name = (
        FLAGS.flag_matrix or benchmark_config.get('flag_matrix', None)
    )
    flag_zip_name = (
        FLAGS.flag_zip or benchmark_config.get('flag_zip', None)
    )
    _AssertFlagMatrixAndZipDefsExist(benchmark_config,
                                     flag_matrix_name,
                                     flag_zip_name)

    # We need to remove the 'flag_matrix', 'flag_matrix_defs', 'flag_zip',
    # 'flag_zip_defs', and 'flag_matrix_filters' keys from the config
    # dictionary since they aren't actually part of the config spec and will
    # cause errors if they are left in.
    benchmark_config.pop('flag_matrix', None)
    benchmark_config.pop('flag_zip', None)

    flag_matrix = benchmark_config.pop(
        'flag_matrix_defs', {}).get(flag_matrix_name, {})
    flag_matrix_filter = benchmark_config.pop(
        'flag_matrix_filters', {}).get(flag_matrix_name, {})
    flag_zip = benchmark_config.pop(
        'flag_zip_defs', {}).get(flag_zip_name, {})

    zipped_axes = []
    crossed_axes = []
    if flag_zip:
      flag_axes = []
      for flag, values in six.iteritems(flag_zip):
        flag_axes.append([{flag: v} for v in values])

      _AssertZipAxesHaveSameLength(flag_axes)

      for flag_config in zip(*flag_axes):
        config = _GetConfigForAxis(benchmark_config, flag_config)
        zipped_axes.append((benchmark_module, config))

      crossed_axes.append([benchmark_tuple[1]['flags'] for
                           benchmark_tuple in zipped_axes])

    for flag, values in sorted(six.iteritems(flag_matrix)):
      crossed_axes.append([{flag: v} for v in values])

    for flag_config in itertools.product(*crossed_axes):
      config = _GetConfigForAxis(benchmark_config, flag_config)
      if (flag_matrix_filter and not eval(
          flag_matrix_filter, {}, config['flags'])):
        continue

      benchmark_config_list.extend([(benchmark_module, config)] *
                                   FLAGS.num_benchmark_copies)

  return benchmark_config_list
