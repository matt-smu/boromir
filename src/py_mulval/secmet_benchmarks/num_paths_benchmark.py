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

CITATION_SHORT = 'Dacier1996'
CITATION_FULL = '''[1]Marc Dacier, Yves Deswarte, and Mohamed Kaâniche. 1996. Quantitative assessment of operational security: Models and tools. Information Systems Security, ed. by SK Katsikas and D. Gritzalis, London, Chapman & Hall (1996), 179–86.
'''

# flags.DEFINE_string('cite_key', None, CITATION_SHORT)
# flags.DEFINE_string('cite_long', None, CITATION_FULL)
flags.DEFINE_string('shortest_ag_path', None, 'use this attack graph')


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

    # nodelist_pre_reduce = list(networkx.algorithms.dag.lexicographical_topological_sort(A))

    origin = list(A.getOriginnodesByAttackerLocated())[0]
    target = list(A.getTargetByNoEgressEdges())[0]
    all_paths_before = list(networkx.all_simple_paths(A,origin,target))

    nodelist_post_reduce = tgraph.getNodeList()
    all_paths_after = list(networkx.all_simple_paths(tgraph,nodelist_post_reduce[0],nodelist_post_reduce[-1]))

    metadata = {# The meta data defining the environment
        'cite_key': CITATION_SHORT,
        'citation':         CITATION_FULL,
        'attack_graph_name': A.name,
        # 'attack_graph_original':   json.dumps(json_graph.node_link_data(A)),
        # 'attack_graph_reduced': json.dumps(json_graph.node_link_data(tgraph)),
        'all_paths_original': json.dumps(all_paths_before),
        'all_paths_reduced': json.dumps(all_paths_after),
        'num_paths_original': len(all_paths_before),
        'num_paths_reduced': len(all_paths_after),
        # 'transition_matrix':   json.dumps(tmatrix.todense().tolist()),
    }
    return sample.Sample('Number of Paths', len(all_paths_after), 'paths', metadata)
  results.append(_RunTest())
  print(results)
  return results



def Cleanup(unused_benchmark_spec):
  pass
