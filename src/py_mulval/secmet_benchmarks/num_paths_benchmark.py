# Copyright 2018 PerfKitBenchmarker Authors. All rights reserved.
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

"""Run struct_secmet."""
import os
import pathlib

from py_mulval import configs
from py_mulval import flags
from py_mulval import genTransMatrix
from py_mulval import mulpy
from py_mulval import py_mulval
from py_mulval import sample

from py_mulval import vm_util

FLAGS = flags.FLAGS

BENCHMARK_NAME = 'num_paths'
BENCHMARK_CONFIG = """
num_paths:
  description: Run num_paths metric
  flags:
    input_file: single_host_1.P
    rule: local_exploit_rules.P
    models_dir: /opt/projects/diss/py-mulval/data/models 
    rules_dir: /opt/projects/diss/py-mulval/data/rules 
    data_dir: /opt/projects/diss/py-mulval/data
    secmet_ag_path: AttackGraph.dot
    # output_dir: 
  # vm_groups:
"""

CITATION_SHORT = 'cite_short'
CITATION_FULL = 'long citation'

# flags.DEFINE_string('cite_key', None, CITATION_SHORT)
# flags.DEFINE_string('cite_long', None, CITATION_FULL)
flags.DEFINE_string('numpaths_ag_path', None, 'use this attack graph')


def GetConfig(user_config):
  return configs.LoadConfig(BENCHMARK_CONFIG, user_config, BENCHMARK_NAME)


def Prepare(benchmark_spec):
  pass


def Run(benchmark_spec):
  """Collect Num_Paths Metrics for an attack graph

  Args:
    benchmark_spec: The benchmark specification. Contains all data that is
        required to run the benchmark.

  Returns:
    A list of sample.Sample objects with the benchmark results.
  """
  results = []

  def _RunTest():

    #####
    ## genTransMatrix
    ####
    # inputDir = FLAGS.base_dir
    inputDir = vm_util.GetTempDir()
    outfileName = os.path.splitext(FLAGS.input_file)[0]  # 'input'
    scriptsDir = '/opt/projects/diss/py-mulval/src/py_mulval/data/secmet'
    # pathlib.Path(FLAGS.output_dir).mkdir(parents=True, exist_ok=True)

    opts = dict()
    opts['scriptsDir'] = scriptsDir
    opts['inputDir'] = inputDir
    opts['outfileName'] = outfileName
    opts['PLOT_INTERMEDIATE_GRAPHS'] = True
    matrix_file = vm_util.PrependTempDir(outfileName + '.csv')
    opts['MatrixFile'] = matrix_file

    # A = AttackGraph(inputDir=inputDir, scriptsDir=scriptsDir, opts=opts
    A = genTransMatrix.AttackGraph(**opts)
    A.name = outfileName
    A.plot2(outfilename=A.name + '_001_orig.png')
    tmatrix = A.getTransMatrix(**opts).dumps()
    # logging.debug('Created weighted transition matrix:\n %s' % tmatrix)

    metadata = {# The meta data defining the environment
        'cite_key': CITATION_SHORT,
        'citation':         CITATION_FULL,
        'attack_graph':   A.name,
        'transition_matrix':   tmatrix,}
    return sample.Sample('Number of Paths', 5, 'paths', metadata)
  results.append(_RunTest())
  print(results)
  return results



def Cleanup(unused_benchmark_spec):
  pass
