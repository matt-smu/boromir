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
"""Contains benchmark imports and a list of benchmarks.

All modules within this package are considered benchmarks, and are loaded
dynamically. Add non-benchmark code to other packages.
"""

from py_mulval import import_util
from py_mulval import flags

FLAGS = flags.FLAGS

# define secmet global flags here
flags.DEFINE_string('secmet_ag_path', None, 'path to find attack graphs')
flags.DEFINE_string('secmet_ag_name', None, 'use this attack graph')
flags.DEFINE_string('secmet_score_dict', None, 'use this score dictionary')
flags.DEFINE_string('input_model_name', None, 'use this mulval model')
flags.DEFINE_boolean('secmet_plot_intermediate_graphs', False, 'Writes graphs to file when true.')
flags.DEFINE_float('secmet_fix_cvss_score', None, 'Applies this cvss score to all vulnerabilities.')

def _LoadBenchmarks():
  return list(import_util.LoadModulesForPath(__path__, __name__))

BENCHMARKS = _LoadBenchmarks()

VALID_BENCHMARKS = {}
for module in BENCHMARKS:
  if module.BENCHMARK_NAME in VALID_BENCHMARKS:
    raise ValueError('There are multiple benchmarks with BENCHMARK_NAME "%s"' %
                     (module.BENCHMARK_NAME))
  VALID_BENCHMARKS[module.BENCHMARK_NAME] = module
