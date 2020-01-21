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

"""Run Mean Effort To Failure benchmark."""
import os
import pathlib
import networkx
from networkx.readwrite import json_graph
import json

from py_mulval import configs
from py_mulval import data
from py_mulval import flags
from py_mulval import genTransMatrix
from py_mulval import mulpy
from py_mulval import py_mulval
from py_mulval import sample
from py_mulval import vm_util

FLAGS = flags.FLAGS

BENCHMARK_NAME = 'metf'
BENCHMARK_CONFIG = """
metf:
  description: Run metf metric
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

CITATION_SHORT = 'Ortalo1999'
CITATION_FULL = '''[1]Rodolphe Ortalo, Yves Deswarte, and Mohamed Kaâniche. 1999. Experimenting with quantitative evaluation tools for monitoring operational security. IEEE Transactions on Software Engineering 25, 5 (1999), 633–650.
'''



def GetConfig(user_config):
  return configs.LoadConfig(BENCHMARK_CONFIG, user_config, BENCHMARK_NAME)


def Prepare(benchmark_spec):
  pass


def Run(benchmark_spec):
  """Collect METF Metrics for an attack graph

  Args:
    benchmark_spec: The benchmark specification. Contains all data that is
        required to run the benchmark.

  Returns:
    A list of sample.Sample objects with the benchmark results.
  """
  results = []

  def _RunTest():

    if not benchmark_spec.attack_graph:
      inputDir = data.ResourcePath('attack_graphs')
      outputDir = vm_util.GetTempDir()
      outfileName = os.path.splitext(FLAGS.input_file)[0]  # 'input'
      scriptsDir = data.ResourcePath('secmet')
      # pathlib.Path(FLAGS.output_dir).mkdir(parents=True, exist_ok=True)

      opts = dict()
      opts['scriptsDir'] = scriptsDir
      opts['inputDir'] = inputDir
      opts['outputDir'] = outputDir
      opts['outfileName'] = outfileName
      opts['PLOT_INTERMEDIATE_GRAPHS'] = FLAGS.secmet_plot_intermediate_graphs
      matrix_file = vm_util.PrependTempDir(outfileName + '.csv')
      opts['MatrixFile'] = matrix_file

      benchmark_spec.attack_graph = genTransMatrix.AttackGraph(**opts)

    A = benchmark_spec.attack_graph
    A.name = outfileName
    if opts['PLOT_INTERMEDIATE_GRAPHS']:
      A.plot2(outfilename=A.name + '_001_orig.png')
    # tgraph, tmatrix, nodelist = A.getTransMatrix(**opts)
    tgraph = A.getReducedGraph(**opts)
    tgraph.scoreTGraph(**opts)
    tgraph.weighTGraph(**opts)
    tgraph.remove_node(tgraph.origin)
    tmatrix, nodelist = tgraph.convertTMatrix()
    tm = tmatrix.todense()

    # mttf = sum(1/\lambda)
    mttf = 1 / (1 - np.diag(tm)[:-1])
    # print(mttf, sum(mttf))

    print(tm)
    # mc = pydtmc.markov_chain.MarkovChain(tm, nodelist)
    mc = pydtmc.markov_chain.MarkovChain.from_matrix(tm, nodelist)

    metadata = {  # The meta data defining the environment
        'cite_key':          CITATION_SHORT, 'citation': CITATION_FULL,
        'attack_graph_name': A.name, 'tmatrix_headers': json.dumps(nodelist),
        'tmatrix_probs':     json.dumps(tmatrix.todense().tolist()),
        'mttf':              json.dumps(mttf.tolist()), }
    return sample.Sample('MTTF', sum(mttf), 'MTTF', metadata)

  results.append(_RunTest())
  # print(results)
  return results


def Cleanup(unused_benchmark_spec):
  pass


def Cleanup(unused_benchmark_spec):
  pass
