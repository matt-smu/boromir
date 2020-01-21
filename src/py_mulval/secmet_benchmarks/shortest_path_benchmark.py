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

"""Run shortest attack path benchmark."""
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

BENCHMARK_NAME = 'shortest_attack_path'
BENCHMARK_CONFIG = """
shortest_attack_path:
  description: Run shortest_attack_path metric
  flags:
    input_file: single_host_1.P
    rule: local_exploit_rules.P
    models_dir: /opt/projects/diss/py-mulval/data/models 
    rules_dir: /opt/projects/diss/py-mulval/data/rules 
    data_dir: /opt/projects/diss/py-mulval/data
    secmet_ag_path: AttackGraph.dot
  #   output_dir: /tmp/mulpy
  # vm_groups:
"""

CITATION_SHORT = 'Ortalo1999'
CITATION_FULL = '''[1]Rodolphe Ortalo, Yves Deswarte, and Mohamed Kaâniche. 1999. Experimenting with quantitative evaluation tools for monitoring operational security. IEEE Transactions on Software Engineering 25, 5 (1999), 633–650.
'''

# flags.DEFINE_string('cite_key', None, CITATION_SHORT)
# flags.DEFINE_string('cite_long', None, CITATION_FULL)
# flags.DEFINE_string('numpaths_ag_path', None, 'use this attack graph')


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


    # A = AttackGraph(inputDir=inputDir, scriptsDir=scriptsDir, opts=opts
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
    tgraph, tmatrix, nodelist = A.getTransMatrix(**opts)

    origin = list(A.getOriginnodesByAttackerLocated())[0]
    target = list(A.getTargetByNoEgressEdges())[0]
    shortest_path_before = list(networkx.all_simple_paths(A,origin,target))
    shortest_path_length_before =  min(shortest_path_before, key=len)

    nodelist_post_reduce = tgraph.getNodeList()
    shortest_paths_after = list(networkx.all_simple_paths(tgraph,nodelist_post_reduce[0],nodelist_post_reduce[-1]))
    shortest_path_length_after = min(shortest_paths_after, key=len)

    metadata = {# The meta data defining the environment
        'cite_key': CITATION_SHORT,
        'citation':         CITATION_FULL,
        'attack_graph_name': A.name,
        # 'attack_graph_original':   json.dumps(json_graph.node_link_data(A)),
        # 'attack_graph_reduced': json.dumps(json_graph.node_link_data(tgraph)),
        'all_paths_before': json.dumps(shortest_path_before),
        'shortest_path_before': shortest_path_length_before,
        'shortest_path_length_before': len(shortest_path_length_before),
        'all_paths_after': shortest_paths_after,
        'shortest_path_after': shortest_path_length_after,
        'shortest_path_length_after': len(shortest_path_length_after),
        # 'transition_matrix':   json.dumps(tmatrix.todense().tolist()),
    }
    return sample.Sample('Shortest Path Length', len(shortest_path_length_after), 'path length', metadata)
  results.append(_RunTest())
  # print(results)
  return results



def Cleanup(unused_benchmark_spec):
  pass
